"""Operator CLI. Live scanning always requires an explicit --live invocation."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import AuditConfig, load_config
from .history import Store
from .reports import build_report, export_report
from .runner import run_audits
from .scheduler import due_period, is_missed
from .summary import CodexSummaryClient, SummaryError, summarize
from .wordfence import FeedError, WordfenceClient


def demo_report(output: Path) -> None:
    scans: list[dict[str, Any]] = []
    for name, status in [("fixture-alpha", "partial"), ("fixture-beta", "failed")]:
        scans.append(
            {
                "id": "test-run-" + name,
                "site_id": name,
                "site_name": "TEST DATA " + name,
                "site_url": "https://audit.example.org/",
                "started": "2026-11-01T03:47:00+00:00",
                "status": status,
                "inventory": {
                    "core_version": "6.9",
                    "php_version": "8.4",
                    "components": [
                        {
                            "id": "fixture-plugin",
                            "type": "plugin",
                            "name": "TEST ONLY demonstration plugin",
                            "slug": "test-only-plugin",
                            "version": "1.0",
                            "status": "active",
                            "update_state": "available",
                            "latest": "2.0",
                            "auto_update": False,
                        }
                    ],
                },
                "feed_status": "controlled-fixture",
                "feed_fetched_at": None,
                "findings": [
                    {
                        "id": "test-update",
                        "status": "open",
                        "title": "TEST DATA update available",
                        "category": "updates",
                        "priority": "low",
                        "confidence": "confirmed",
                        "evidence": "Controlled fixture, not a real client finding.",
                        "details": {"installed": "1.0", "available": "2.0"},
                        "remediation": "TEST action: review and test the update.",
                    }
                ]
                if status == "partial"
                else [],
                "checks": [
                    {
                        "key": "inventory",
                        "status": "unknown",
                        "evidence": "TEST DATA: missing verification example.",
                    }
                ],
                "changes": [],
                "limitations": [
                    "TEST DATA ONLY. No live website, feed or WordPress integration was used."
                ],
            }
        )
    report = build_report(
        scans, registered_sites=2, now=datetime(2026, 11, 1, 3, 47, tzinfo=UTC), test_data=True
    )
    report["summary"] = summarize(report)
    export_report(report, output, "consolidated")
    for scan in scans:
        export_report(
            build_report([scan], registered_sites=1, test_data=True), output, scan["site_id"]
        )


def offline_files(directory: Path | None, config: AuditConfig) -> dict[str, Any]:
    values = {}
    if directory:
        for site in config.sites:
            path = directory / (site.id + ".json")
            if path.is_file():
                if path.stat().st_size > 10_000_000:
                    raise ValueError("Offline input size limit")
                values[site.id] = json.loads(path.read_text(encoding="utf-8-sig"))
    return values


def secret_environment(config: AuditConfig) -> dict[str, str]:
    environment = dict(os.environ)
    bundle = json.loads(environment.get("SENTINEL_CONNECTOR_TOKENS_JSON", "{}"))
    allowed = {s.connector_token_env for s in config.sites if s.connector_token_env}
    if (
        not isinstance(bundle, dict)
        or len(bundle) > 500
        or any(
            k not in allowed or not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9]{64}", v)
            for k, v in bundle.items()
        )
    ):
        raise ValueError("Invalid connector secret bundle")
    environment.update(bundle)
    return environment


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Authorized, read-only WordPress audits")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--config", type=Path, required=True)
    demo = commands.add_parser("demo")
    demo.add_argument("--output", type=Path, required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("--config", type=Path, required=True)
    scan.add_argument("--db", type=Path, required=True)
    scan.add_argument("--output", type=Path, required=True)
    scan.add_argument("--live", action="store_true")
    scan.add_argument("--site")
    scan.add_argument("--scheduled", action="store_true")
    scan.add_argument("--inventory-dir", type=Path)
    scan.add_argument("--integrity-dir", type=Path)
    scan.add_argument("--codex-summary", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            demo_report(args.output)
            print("Generated clearly labeled TEST DATA reports.")
            return 0
        config = load_config(args.config)
        if args.command == "validate":
            print(f"Registry valid: {len(config.sites)} sites. No network requests made.")
            return 0
        if not args.live:
            print("Live execution requires explicit --live and an authorized registry.")
            return 2
        environment = secret_environment(config)
        if args.site:
            sites = [s for s in config.sites if s.id == args.site]
            if not sites:
                raise ValueError("Unknown site identifier")
            config = config.model_copy(update={"sites": sites})
        now = datetime.now(UTC)
        store = Store(args.db)
        if args.scheduled:
            period = due_period(config.schedule, now)
            if not period:
                print("Monthly execution is not due.")
                return 0
            enabled = [s for s in config.sites if s.enabled]
            previous = [store.latest(s.id) for s in enabled]
            if enabled and all(
                p
                and p["status"] == "complete"
                and due_period(config.schedule, datetime.fromisoformat(p["started"])) == period
                for p in previous
            ):
                print("This monthly audit is already complete.")
                return 0
            if is_missed(config.schedule, now, None):
                print("Monthly audit is late or incomplete; attempting recovery.")
        feed = None
        if any(s.enabled and set(s.methods) & {"inventory", "wpcli"} for s in config.sites):
            try:
                feed = WordfenceClient(
                    os.environ.get("SENTINEL_WORDFENCE_API_KEY", ""),
                    terms_accepted=os.environ.get("SENTINEL_WORDFENCE_TERMS_ACCEPTED") == "yes",
                ).fetch()
            except FeedError as exc:
                print(
                    "Intelligence unavailable: "
                    + exc.kind
                    + ". Inventory collection will continue with incomplete advisory coverage."
                )
        stop = threading.Event()
        previous_handlers = {}
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGINT, signal.SIGTERM):
                previous_handlers[sig] = signal.signal(sig, lambda *_: stop.set())
        try:
            result = run_audits(
                config,
                store,
                args.output,
                environment=environment,
                feed=feed,
                cancel=stop.is_set,
                offline_inventories=offline_files(args.inventory_dir, config),
                integrity_manifests=offline_files(args.integrity_dir, config),
            )
        finally:
            for sig, handler in previous_handlers.items():
                signal.signal(sig, handler)
        if args.codex_summary and "report" in result:
            report = result["report"]
            try:
                selection = CodexSummaryClient(
                    os.environ.get("SENTINEL_OPENAI_API_KEY", ""),
                    model=os.environ.get("SENTINEL_CODEX_MODEL", ""),
                ).select(report)
                report["summary"] = summarize(report, selection)
            except SummaryError:
                report["summary"]["ai_review"] = (
                    "Unavailable or rejected; deterministic summary retained."
                )
            export_report(report, args.output, "consolidated")
        print(
            json.dumps(
                {
                    "status": result["status"],
                    "sites": [
                        {"site_id": s["site_id"], "scan_id": s["id"], "status": s["status"]}
                        for s in result["scans"]
                    ],
                }
            )
        )
        return 0 if result["status"] == "complete" else 1
    except (ValueError, OSError):
        print(
            "Operation failed: configuration, input, storage or report validation error. Secret-bearing details omitted."
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
