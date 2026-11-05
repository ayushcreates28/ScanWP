"""Read-only scan orchestration and isolated, persistent per-site outcomes."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import defaultdict
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .config import AuditConfig, SiteConfig
from .environment import assess_settings
from .history import Store, canonicalize
from .integrity import compare_manifest, validate_manifest
from .inventory import fetch_inventory, parse_inventory
from .matching import internal_priority, match_advisory
from .reports import build_report, export_report
from .scanner import scan_public
from .summary import summarize
from .transport import GuardedClient
from .wordfence import FeedSnapshot, Record, parsed_date


class Cancellation:
    def __init__(self, check: Callable[[], bool]) -> None:
        self.check = check

    def is_set(self) -> bool:
        return self.check()


def redact(value: Any, secrets: list[str]) -> Any:
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[REDACTED]")
        return value
    if isinstance(value, dict):
        return {redact(k, secrets): redact(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secrets) for v in value]
    if isinstance(value, tuple):
        return tuple(redact(v, secrets) for v in value)
    return value


def key_for(*parts: str) -> str:
    return hashlib.sha256(json.dumps(parts).encode()).hexdigest()[:32]


def check_finding(check: dict[str, Any]) -> dict[str, Any]:
    status = (
        "open" if check["status"] == "fail" else "clear" if check["status"] == "pass" else "unknown"
    )
    return {
        "id": "check:" + key_for(check["key"], check.get("path", "")),
        "status": status,
        "title": check["key"],
        "priority": check.get("severity", "unknown").replace("info", "informational"),
        "category": check.get("category", "configuration"),
        "evidence": check["evidence"],
        "confidence": "confirmed" if status in {"open", "clear"} else "unknown",
        "remediation": check.get("remediation", "Review this observation with the administrator."),
        "references": [check["source_url"]] if check.get("source_url") else [],
        "details": {"path": check.get("path")},
    }


def inventory_findings(
    inventory: dict[str, Any],
    index: dict[tuple[str, str], list[Record]],
    fresh: bool,
    site: SiteConfig,
    now: datetime,
) -> list[dict[str, Any]]:
    findings = []
    captured = parsed_date(inventory["captured_at"])
    recent = bool(captured and timedelta(minutes=-5) <= now - captured <= timedelta(hours=24))
    for component in inventory["components"]:
        if component["type"] == "php":
            continue
        update_at = parsed_date(
            inventory["updates_checked_at"].get(
                {"plugin": "plugins", "theme": "themes", "core": "core"}[component["type"]]
            )
        )
        updates_fresh = bool(
            recent and update_at and timedelta(minutes=-5) <= now - update_at <= timedelta(hours=24)
        )
        update_status = component["update_state"] if updates_fresh else "unknown"
        findings.append(
            {
                "id": "update:" + key_for(component["id"]),
                "status": {"available": "open", "current": "clear"}.get(update_status, "unknown"),
                "title": "Component update: " + component["name"],
                "category": "updates",
                "priority": "low" if update_status == "available" else "unknown",
                "confidence": "confirmed" if update_status != "unknown" else "unknown",
                "evidence": "Authenticated update cache state="
                + update_status
                + "; checked="
                + str(update_at),
                "component_id": component["id"],
                "details": {
                    "installed": component["version"],
                    "latest": component["latest"],
                    "activation": component["status"],
                },
                "remediation": "Review the changelog, back up and test a supported update in staging before an approved production change.",
            }
        )
        identity = component.get("slug_source") in {"core", "wordpress.org", "update-api"}
        candidate = {**component, "identity_confirmed": identity}
        for record in index.get((component["type"], component["slug"]), []):
            match = match_advisory(candidate, record)
            classification = match["classification"] if fresh and recent else "unknown"
            findings.append(
                {
                    "id": "advisory:" + key_for(component["id"], record.id),
                    "status": "open"
                    if classification in {"affected", "potential"}
                    else "clear"
                    if classification == "not_affected" and identity
                    else "unknown",
                    "title": record.title,
                    "category": "vulnerability",
                    "priority": internal_priority(record, {"criticality": site.criticality}),
                    "confidence": "confirmed"
                    if classification == "affected"
                    else "potential"
                    if classification == "potential"
                    else "unknown",
                    "evidence": "Version-range match="
                    + classification
                    + "; this is not evidence of exploitation or malware.",
                    "component_id": component["id"],
                    "advisory_id": record.id,
                    "cvss": record.score,
                    "published_severity": record.published_severity,
                    "references": list(record.references),
                    "copyrights": record.copyrights,
                    "details": {
                        "installed": component["version"],
                        "activation": component["status"],
                        "affected_versions": [
                            s["affected_versions"]
                            for s in record.software
                            if s["slug"] == component["slug"]
                        ],
                        "corrected_versions": match["corrected_versions"],
                        "cve": record.cve,
                        "published": record.published.isoformat() if record.published else None,
                        "record_updated": record.updated.isoformat() if record.updated else None,
                    },
                    "remediation": "Verify component identity and affected version; test an applicable corrected branch before an approved update. Corrected versions: "
                    + ", ".join(match["corrected_versions"]),
                }
            )
    return findings


def run_audits(
    config: AuditConfig,
    store: Store,
    output: Path,
    *,
    environment: dict[str, str],
    feed: FeedSnapshot | None = None,
    client_factory: Callable[[SiteConfig, Any], GuardedClient] | None = None,
    cancel: Callable[[], bool] = lambda: False,
    now: datetime | None = None,
    offline_inventories: dict[str, Any] | None = None,
    integrity_manifests: dict[str, Any] | None = None,
) -> dict[str, Any]:
    instant = now or datetime.now(UTC)
    owner = str(uuid.uuid4())
    if not store.acquire("audit-run", owner, instant, timedelta(hours=6)):
        return {"status": "overlap", "scans": []}
    index: dict[tuple[str, str], list[Record]] = defaultdict(list)
    if feed:
        for record in feed.records:
            for identity in {(s["type"], s["slug"]) for s in record.software}:
                index[identity].append(record)
    scans = []
    alerts = []
    fresh = feed is not None and not feed.is_stale(instant)
    event = Cancellation(cancel)
    try:
        secrets = [environment.get(s.connector_token_env or "", "") for s in config.sites]
        secrets.extend(
            environment.get(k, "")
            for k in ("SENTINEL_WORDFENCE_API_KEY", "SENTINEL_OPENAI_API_KEY")
        )
        if feed:
            safe_feed = FeedSnapshot(
                tuple(Record(**redact(asdict(record), secrets)) for record in feed.records),
                feed.fetched_at,
                feed.source,
            )
            store.save_feed(safe_feed)
        store.recover(instant, timedelta(hours=6))
        for site in config.sites:
            scan_id = store.begin(site.id, instant)
            doc: dict[str, Any] = {
                "site_name": site.name,
                "site_url": site.production_url,
                "methods": site.methods,
                "findings": [],
                "checks": [],
                "inventory": {},
                "feed_status": "fresh" if fresh else "stale" if feed else "unavailable",
                "feed_fetched_at": feed.fetched_at.isoformat() if feed else None,
                "limitations": [
                    "Version matching does not establish exploitation or malware. No remediation was performed.",
                    "Custom, premium and must-use components can require manual identity/reference verification.",
                    "PHP version alone cannot establish complete hosting patch status or vendor backports.",
                ],
            }
            status = "complete"
            if not site.enabled:
                status = "skipped"
            elif cancel():
                status = "cancelled"
            else:
                try:
                    factory = client_factory or (lambda s, c: GuardedClient(s, cancel=c))
                    result: dict[str, Any]
                    with factory(site, event) as client:
                        if "public" in site.methods:
                            public = scan_public(client)
                            doc["checks"].extend(public["checks"])
                            doc["detection"] = public["detection"]
                            doc["requests"] = public["requests"]
                            if public["status"] != "complete":
                                status = public["status"]
                        if "inventory" in site.methods or "wpcli" in site.methods:
                            if (
                                "wpcli" in site.methods
                                and offline_inventories
                                and site.id in offline_inventories
                            ):
                                result = {
                                    "status": "complete",
                                    "inventory": parse_inventory(
                                        offline_inventories[site.id], site.production_url
                                    ),
                                }
                            elif "inventory" in site.methods:
                                result = fetch_inventory(client, environment)
                            else:
                                result = {"status": "failed", "error": "offline_inventory_missing"}
                            if result["status"] != "complete":
                                status = "failed" if status == "complete" else "partial"
                                doc["limitations"].append(
                                    "Inventory failed: " + result.get("error", "unknown")
                                )
                            else:
                                inventory = result["inventory"]
                                doc["inventory"] = inventory
                                doc["findings"].extend(
                                    inventory_findings(inventory, index, fresh, site, instant)
                                )
                                doc["checks"].extend(
                                    asdict(c) for c in assess_settings(inventory["settings"])
                                )
                                if not fresh:
                                    status = "partial"
                                    doc["limitations"].append(
                                        "Vulnerability intelligence unavailable or stale; advisory checks are not complete."
                                    )
                        else:
                            status = "partial"
                            doc["limitations"].append(
                                "Authenticated inventory and full vulnerability matching were not requested; installed components remain unknown."
                            )
                    if "integrity" in site.methods:
                        manifest = (integrity_manifests or {}).get(site.id)
                        if not manifest:
                            status = "partial"
                            doc["limitations"].append(
                                "Approved integrity metadata was not supplied."
                            )
                        else:
                            validate_manifest(manifest["files"])
                            # latest is the running row; find the preceding captured manifest.
                            prior = next(
                                (
                                    r
                                    for r in reversed(store.scans())
                                    if r["site_id"] == site.id
                                    and r["id"] != scan_id
                                    and r.get("integrity_manifest")
                                ),
                                None,
                            )
                            baseline = manifest.get("trusted_reference") or (
                                prior["integrity_manifest"]["files"] if prior else {}
                            )
                            observations = compare_manifest(
                                manifest["files"],
                                baseline,
                                trusted=bool(manifest.get("trusted_reference")),
                                complete=manifest.get("complete") is True,
                            )
                            doc["integrity_manifest"] = manifest
                            doc["integrity"] = observations
                            for observation in observations:
                                state = observation["state"]
                                doc["findings"].append(
                                    {
                                        "id": "integrity:" + key_for(observation["path"]),
                                        "status": "clear"
                                        if state in {"known-clean", "unchanged"}
                                        else "unknown"
                                        if state == "unverified"
                                        else "open",
                                        "title": "File integrity: " + observation["path"],
                                        "category": "integrity",
                                        "priority": "medium",
                                        "confidence": "confirmed"
                                        if state != "unverified"
                                        else "unknown",
                                        "evidence": "File state="
                                        + state
                                        + ". Modification is not proof of malware.",
                                        "details": observation,
                                    }
                                )
                            if not manifest.get("complete"):
                                status = "partial"
                    doc["findings"].extend(
                        check_finding(c) for c in doc["checks"] if c["status"] != "info"
                    )
                    if (
                        any(f["status"] == "unknown" for f in doc["findings"])
                        and status == "complete"
                    ):
                        status = "partial"
                    if cancel():
                        status = "cancelled"
                except Exception:
                    # Provider exceptions and remote bodies may contain credentials.
                    status = "failed"
                    doc["error"] = "site_execution"
                    doc["limitations"].append(
                        "Site execution failed; internal exception text is deliberately omitted."
                    )
            doc = redact(doc, secrets)
            doc["findings"] = canonicalize(doc["findings"])
            completed = store.finish(scan_id, status, doc)
            scans.append(completed)
            if site.enabled and status != "complete":
                alerts.append({"site_id": site.id, "scan_id": scan_id, "status": status})
            try:
                export_report(
                    build_report([completed], registered_sites=1, timezone=site.reporting.timezone),
                    output,
                    site.id,
                )
            except Exception:
                scans[-1] = store.report_failed(scan_id)
                alerts.append({"site_id": site.id, "scan_id": scan_id, "status": "report_failed"})
        portfolio = build_report(
            scans, registered_sites=len(config.sites), timezone=config.schedule.timezone
        )
        portfolio["summary"] = summarize(portfolio)
        try:
            export_report(portfolio, output, "consolidated")
        except Exception:
            scans = [store.report_failed(scan["id"]) for scan in scans]
            alerts.append({"status": "consolidated_report_failed"})
            portfolio = build_report(
                scans, registered_sites=len(config.sites), timezone=config.schedule.timezone
            )
            portfolio["summary"] = summarize(portfolio)
        output.joinpath("alerts.json").write_text(json.dumps(alerts, indent=2), encoding="utf-8")
        store.backup(output / "history.sqlite")
        return {
            "status": "partial" if alerts else "complete",
            "scans": scans,
            "alerts": alerts,
            "report": portfolio,
        }
    finally:
        store.release("audit-run", owner)
