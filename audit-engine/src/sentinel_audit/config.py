"""Strict, secret-free registry configuration. No network I/O occurs on load."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Literal, Self
from urllib.parse import unquote, urlsplit, urlunsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator


def normalize_url(value: str) -> str:
    if not isinstance(value, str) or len(value) > 2048 or any(c.isspace() for c in value):
        raise ValueError("A bounded absolute HTTP(S) URL without whitespace is required")
    if "\\" in value:
        raise ValueError("Backslashes are not permitted")
    try:
        parts = urlsplit(value)
        if parts.scheme not in {"https", "http"} or not parts.hostname:
            raise ValueError("An absolute HTTP(S) URL is required")
        if (
            parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
        ):
            raise ValueError("Credentials, query strings and fragments are not permitted")
        if parts.port not in {None, 80, 443}:
            raise ValueError("Only standard HTTP(S) ports are permitted")
        hostname = parts.hostname.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Invalid target URL") from exc
    if hostname.endswith(".") or "%" in hostname or "." not in hostname:
        raise ValueError("A public DNS hostname is required")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", hostname):
        raise ValueError("Invalid DNS hostname")
    if re.fullmatch(r"(?:0x[0-9a-f]+|[0-9.]+)", hostname):
        raise ValueError("IP literals are not permitted")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("IP literals are not permitted")
    if hostname.rsplit(".", 1)[-1] in {
        "local",
        "internal",
        "localhost",
        "invalid",
        "test",
        "example",
        "onion",
    } or hostname.endswith(".home.arpa"):
        raise ValueError("Private and reserved hostnames are not permitted")
    path = parts.path or "/"
    decoded = path
    for _ in range(3):
        decoded = unquote(decoded)
    if (
        "\\" in decoded
        or any(ord(c) < 32 or ord(c) == 127 for c in decoded)
        or any(p in {".", ".."} for p in decoded.split("/"))
    ):
        raise ValueError("Unsafe path")
    if not path.endswith("/"):
        path += "/"
    # Normalize default ports so origin comparison cannot be confused by aliases.
    port = parts.port
    if port is not None and port != (443 if parts.scheme == "https" else 80):
        raise ValueError("Port must match the URL scheme")
    return urlunsplit((parts.scheme, hostname, path, "", ""))


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, validate_default=True)


class Schedule(StrictModel):
    day: int = Field(default=1, ge=1, le=28)
    hour: int = Field(default=9, ge=0, le=23)
    minute: int = Field(default=17, ge=0, le=59)
    timezone: str = "Asia/Kolkata"

    @field_validator("timezone")
    @classmethod
    def valid_timezone(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("Unknown IANA timezone") from exc
        return value


class Reporting(StrictModel):
    formats: list[Literal["json", "xlsx", "html", "pdf"]] = Field(
        default=["json", "xlsx", "html", "pdf"], min_length=1, max_length=4
    )
    timezone: str = "Asia/Kolkata"

    @field_validator("timezone")
    @classmethod
    def valid_timezone(cls, value: str) -> str:
        return Schedule.valid_timezone(value)


class SiteConfig(StrictModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    name: str = Field(min_length=1, max_length=200)
    production_url: str
    staging_url: str | None = None
    staging_authorized: StrictBool = False
    environment: Literal["production", "staging", "development"] = "production"
    authorized: StrictBool
    enabled: StrictBool = True
    methods: list[Literal["public", "inventory", "wpcli", "integrity"]] = Field(
        default=["public"], min_length=1, max_length=4
    )
    connector_token_env: str | None = Field(
        default=None, pattern=r"^SENTINEL_[A-Z][A-Z0-9_]{2,127}$"
    )
    rate_limit_per_second: float = Field(default=0.5, gt=0, le=2)
    timeout_seconds: int = Field(default=15, ge=1, le=30)
    max_requests: int = Field(default=25, ge=1, le=100)
    max_response_bytes: int = Field(default=5_000_000, ge=1024, le=10_000_000)
    criticality: Literal["standard", "high", "critical"] = "standard"
    reporting: Reporting = Field(default_factory=Reporting)

    @field_validator("production_url", "staging_url")
    @classmethod
    def valid_url(cls, value: str | None) -> str | None:
        return normalize_url(value) if value is not None else None

    @model_validator(mode="after")
    def approved_scope(self) -> Self:
        if not self.authorized:
            raise ValueError("Explicit website authorization is required")
        if self.staging_url and not self.staging_authorized:
            raise ValueError("Staging must be separately authorized")
        if len(self.methods) != len(set(self.methods)):
            raise ValueError("Duplicate scanning methods")
        if "inventory" in self.methods and (
            not self.connector_token_env or not self.production_url.startswith("https://")
        ):
            raise ValueError(
                "Authenticated inventory requires HTTPS and a secret environment reference"
            )
        return self

    @property
    def allowed_hosts(self) -> frozenset[str]:
        urls = [self.production_url] + ([self.staging_url] if self.staging_url else [])
        return frozenset(str(urlsplit(url).hostname) for url in urls)


class AuditConfig(StrictModel):
    schema_version: Literal[1] = 1
    sites: list[SiteConfig] = Field(default_factory=list, max_length=500)
    schedule: Schedule = Field(default_factory=Schedule)

    @model_validator(mode="after")
    def unique_registry(self) -> Self:
        ids: set[str] = set()
        hosts: set[str] = set()
        for site in self.sites:
            if site.id in ids or hosts.intersection(site.allowed_hosts):
                raise ValueError("Duplicate site identifier or host")
            ids.add(site.id)
            hosts.update(site.allowed_hosts)
        return self


def load_config(path: Path) -> AuditConfig:
    if path.stat().st_size > 2_000_000:
        raise ValueError("Registry file exceeds the 2 MB limit")
    return AuditConfig.model_validate(json.loads(path.read_text(encoding="utf-8-sig")))
