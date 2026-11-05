"""Restricted connector and offline WP-CLI inventory normalization."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr, ValidationError

from .config import normalize_url
from .transport import GuardedClient


class InventoryError(ValueError):
    """The inventory could not be validated. Messages never contain payload data."""


class ExternalModel(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)


class Component(ExternalModel):
    id: StrictStr = Field(min_length=1, max_length=250)
    type: Literal["core", "php", "plugin", "theme"]
    slug: StrictStr = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,149}$")
    name: StrictStr = Field(min_length=1, max_length=250)
    version: StrictStr | None = Field(default=None, max_length=100)
    status: Literal[
        "runtime",
        "active",
        "inactive",
        "network-active",
        "must-use",
        "drop-in",
        "parent",
        "unknown",
    ]
    update_state: Literal["available", "current", "unknown"] = Field(
        default="unknown", alias="updateState"
    )
    latest: StrictStr | None = Field(default=None, max_length=100)
    auto_update: StrictBool | None = Field(default=None, alias="autoUpdate")
    slug_source: StrictStr | None = Field(default=None, alias="slugSource", max_length=100)
    requires_php: StrictStr | None = Field(default=None, alias="requiresPHP", max_length=100)
    requires_wordpress: StrictStr | None = Field(default=None, alias="requiresWP", max_length=100)


class Settings(ExternalModel):
    debug: StrictBool | None = None
    debugDisplay: StrictBool | None = None
    fileEditorDisabled: StrictBool | None = None
    fileModsDisabled: StrictBool | None = None
    forceSSLAdmin: StrictBool | None = None
    registrationEnabled: StrictBool | None = None
    defaultRole: StrictStr | None = Field(default=None, max_length=100)
    phpSecuritySupported: StrictBool | None = None
    phpRecommended: StrictStr | None = Field(default=None, max_length=100)


class Site(ExternalModel):
    url: StrictStr = Field(max_length=2048)
    name: StrictStr = Field(max_length=250)
    multisite: StrictBool = False


class Snapshot(ExternalModel):
    schema_tag: Literal["sentinel-inventory/v1"] = Field(alias="schema")
    generatedAt: StrictStr = Field(max_length=60)
    site: Site
    components: list[Component] = Field(min_length=1, max_length=500)
    settings: Settings = Field(default_factory=Settings)
    updatesCheckedAt: dict[str, StrictStr | None] = Field(default_factory=dict)


def parse_inventory(raw: Any, expected_url: str) -> dict[str, Any]:
    try:
        snapshot = Snapshot.model_validate(raw)
        captured = datetime.fromisoformat(snapshot.generatedAt)
        if captured.tzinfo is None or (captured - datetime.now(UTC)).total_seconds() > 300:
            raise ValueError("Invalid snapshot time")
        if normalize_url(snapshot.site.url) != normalize_url(expected_url):
            raise ValueError("Wrong site")
        ids = [c.id for c in snapshot.components]
        core = [c for c in snapshot.components if c.type == "core"]
        php = [c for c in snapshot.components if c.type == "php"]
        if len(ids) != len(set(ids)) or len(core) != 1 or len(php) > 1:
            raise ValueError("Invalid component set")
        if len(snapshot.updatesCheckedAt) > 3 or any(
            k not in {"core", "plugins", "themes"} for k in snapshot.updatesCheckedAt
        ):
            raise ValueError("Invalid update metadata")
        for timestamp in snapshot.updatesCheckedAt.values():
            if timestamp is not None:
                checked = datetime.fromisoformat(timestamp)
                if checked.tzinfo is None or (checked - datetime.now(UTC)).total_seconds() > 300:
                    raise ValueError("Invalid update timestamp")
    except (ValidationError, ValueError, TypeError):
        raise InventoryError(
            "Inventory schema, site identity or metadata validation failed"
        ) from None
    return {
        "site_url": normalize_url(snapshot.site.url),
        "site_name": snapshot.site.name,
        "captured_at": captured.isoformat(),
        "multisite": snapshot.site.multisite,
        "core_version": core[0].version,
        "php_version": php[0].version if php else None,
        "components": [c.model_dump() for c in snapshot.components],
        "settings": snapshot.settings.model_dump(exclude_none=True),
        "updates_checked_at": snapshot.updatesCheckedAt,
    }


def fetch_inventory(client: GuardedClient, environment: dict[str, str]) -> dict[str, Any]:
    site = client.site
    if not site.enabled or "inventory" not in site.methods:
        return {"status": "skipped", "error": "method", "inventory": None}
    token = environment.get(site.connector_token_env or "", "")
    if not re.fullmatch(r"[A-Za-z0-9._~-]{8,512}", token):
        return {"status": "failed", "error": "credentials", "inventory": None}
    result = client.get(
        site.production_url + "wp-json/sentinel-audit/v1/inventory",
        headers={"Authorization": "Bearer " + token},
    )
    if result.status in {401, 403}:
        error = "authentication"
    elif result.status in {404, 405}:
        error = "endpoint"
    elif not result.complete or result.status != 200:
        error = result.error or "http"
    else:
        try:
            inventory = parse_inventory(json.loads(result.body), site.production_url)
            return {"status": "complete", "error": None, "inventory": inventory}
        except (InventoryError, ValueError, UnicodeError):
            error = "schema"
    return {"status": "failed", "error": error, "inventory": None}


def parse_wpcli(
    core_version: str,
    plugins: list[dict[str, Any]],
    themes: list[dict[str, Any]],
    site_url: str,
    php_version: str | None = None,
) -> dict[str, Any]:
    components: list[dict[str, Any]] = [
        {
            "id": "core",
            "type": "core",
            "name": "WordPress",
            "slug": "wordpress",
            "version": core_version,
            "status": "runtime",
            "updateState": "unknown",
        }
    ]
    if php_version:
        components.append(
            {
                "id": "php",
                "type": "php",
                "name": "PHP",
                "slug": "php",
                "version": php_version,
                "status": "runtime",
                "updateState": "unknown",
            }
        )
    states = {
        "active-network": "network-active",
        "must-use": "must-use",
        "dropin": "drop-in",
        "active": "active",
        "inactive": "inactive",
        "parent": "parent",
    }
    for kind, records in [("plugin", plugins), ("theme", themes)]:
        if len(records) > 500:
            raise InventoryError("WP-CLI inventory exceeds the component limit")
        for record in records:
            if not isinstance(record, dict):
                raise InventoryError("WP-CLI component metadata is not an object")
            slug = record.get("name")
            components.append(
                {
                    "id": f"{kind}:{slug}",
                    "type": kind,
                    "slug": slug,
                    "name": record.get("title") or slug,
                    "version": record.get("version"),
                    "status": states.get(record.get("status", ""), "unknown"),
                    "updateState": "available"
                    if record.get("update") == "available"
                    else "current"
                    if record.get("update") == "none"
                    else "unknown",
                    "latest": record.get("update_version"),
                    "slugSource": "wp-cli",
                }
            )
    return parse_inventory(
        {
            "schema": "sentinel-inventory/v1",
            "generatedAt": datetime.now(UTC).isoformat(),
            "site": {"url": site_url, "name": "WP-CLI import", "multisite": False},
            "components": components,
        },
        site_url,
    )
