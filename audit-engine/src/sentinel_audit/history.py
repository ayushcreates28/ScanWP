"""Canonical findings and transactional SQLite history; absence never means resolved."""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import __version__
from .wordfence import FeedError, FeedSnapshot, Record, parsed_date, safe_reference


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str = Field(min_length=1, max_length=300, pattern=r"^[^/\\\x00-\x1f]+$")
    status: Literal["open", "clear", "unknown"]
    title: str = Field(min_length=1, max_length=1000)
    priority: Literal["critical", "high", "medium", "low", "informational", "unknown"] = "unknown"
    category: str = Field(max_length=100)
    evidence: str = Field(max_length=20_000)
    confidence: Literal["confirmed", "potential", "unknown"] = "unknown"
    references: list[str] = Field(default_factory=list, max_length=100)
    remediation: str = Field(default="Review with the administrator.", max_length=20_000)
    component_id: str | None = Field(default=None, max_length=250)
    advisory_id: str | None = Field(default=None, max_length=120)
    published_severity: str | None = Field(default=None, max_length=100)
    cvss: float | None = Field(default=None, ge=0, le=10)
    details: dict[str, Any] = Field(default_factory=dict)
    copyrights: dict[str, Any] = Field(default_factory=dict)

    @field_validator("references")
    @classmethod
    def valid_refs(cls, values: list[str]) -> list[str]:
        if not all(safe_reference(v) for v in values):
            raise ValueError("Invalid reference")
        return values


def safe_document(data: Any) -> str:
    def inspect(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if str(key).lower() in {
                    "password",
                    "authorization",
                    "token",
                    "api_key",
                    "db_password",
                    "secret",
                    "cookie",
                    "set-cookie",
                }:
                    raise ValueError("Secret fields must not be persisted")
                inspect(item)
        elif isinstance(value, list):
            for item in value:
                inspect(item)

    inspect(data)
    encoded = json.dumps(data, ensure_ascii=True, allow_nan=False, sort_keys=True)
    if len(encoded) > 10_000_000:
        raise ValueError("Document size limit")
    return encoded


def canonicalize(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    safe_document(findings)
    if len(findings) > 10_000:
        raise ValueError("Finding limit")
    result: dict[str, dict[str, Any]] = {}
    for raw in findings:
        item = Finding.model_validate(raw).model_dump()
        key = item["id"]
        if key in result and result[key] != item:
            raise ValueError("Conflicting duplicate findings")
        result[key] = item
    return [result[key] for key in sorted(result)]


def compare_findings(
    current: list[dict[str, Any]], previous: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    now = {f["id"]: f for f in canonicalize(current)}
    old = {f["id"]: f for f in canonicalize(previous)}
    changes = []
    for key in sorted(now.keys() | old.keys()):
        n = now.get(key)
        p = old.get(key)
        if n and n["status"] == "open":
            change = "recurring" if p and p["status"] != "clear" else "new"
        elif p and p["status"] != "clear":
            change = (
                "not_comparable"
                if n is None
                else "resolved"
                if n["status"] == "clear"
                else "verification"
            )
        elif n and n["status"] == "unknown":
            change = "verification"
        else:
            continue
        changes.append({"id": key, "change": change, "current": n, "previous": p})
    return changes


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                  id TEXT PRIMARY KEY,site_id TEXT NOT NULL,started TEXT NOT NULL,
                  completed TEXT,status TEXT NOT NULL,document TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS scans_site ON scans(site_id,started);
                CREATE TABLE IF NOT EXISTS leases (key TEXT PRIMARY KEY,owner TEXT NOT NULL,expires TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS metadata (version INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS intelligence (id TEXT PRIMARY KEY,record TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS feed_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1),fetched_at TEXT NOT NULL,source TEXT NOT NULL,count INTEGER NOT NULL);
                INSERT INTO metadata SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM metadata);
            """)
            if connection.execute("SELECT version FROM metadata").fetchone()[0] != 1:
                raise ValueError("Unsupported database schema version")
        # chmod is advisory on Windows; private runner directory/ACL is required.
        path.chmod(0o600)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def begin(self, site_id: str, started: datetime) -> str:
        if started.tzinfo is None:
            raise ValueError("Aware time required")
        run_id = str(uuid.uuid4())
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO scans VALUES (?,?,?,?,?,?)",
                (run_id, site_id, started.astimezone(UTC).isoformat(), None, "running", "{}"),
            )
        return run_id

    def finish(self, run_id: str, status: str, document: dict[str, Any]) -> dict[str, Any]:
        if status not in {"complete", "partial", "failed", "skipped", "cancelled", "interrupted"}:
            raise ValueError("Invalid terminal status")
        document = {
            **document,
            "findings": canonicalize(document.get("findings", [])),
            "scanner_version": __version__,
        }
        safe_document(document)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM scans WHERE id=?", (run_id,)).fetchone()
            if row is None or row["status"] != "running":
                raise ValueError("Scan is not running")
            previous = connection.execute(
                "SELECT document FROM scans WHERE site_id=? AND id<>? AND status<>'running' ORDER BY started DESC,rowid DESC LIMIT 1",
                (row["site_id"], run_id),
            ).fetchone()
            prior = json.loads(previous[0]) if previous else {}
            changes = compare_findings(
                document["findings"], prior.get("outstanding", prior.get("findings", []))
            )
            document["changes"] = changes
            outstanding = {f["id"]: f for f in document["findings"] if f["status"] != "clear"}
            for change in changes:
                if change["change"] == "not_comparable":
                    p = {**change["previous"], "status": "unknown", "confidence": "unknown"}
                    outstanding[p["id"]] = p
            document["outstanding"] = list(outstanding.values())
            connection.execute(
                "UPDATE scans SET completed=?,status=?,document=? WHERE id=?",
                (datetime.now(UTC).isoformat(), status, safe_document(document), run_id),
            )
        return self.get(run_id)

    def report_failed(self, run_id: str) -> dict[str, Any]:
        """Keep terminal scans retryable when a required export fails."""
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM scans WHERE id=?", (run_id,)).fetchone()
            if row is None or row["status"] == "running":
                raise ValueError("A terminal scan is required for report failure")
            document = json.loads(row["document"])
            document["report_status"] = "failed"
            status = "partial" if row["status"] == "complete" else row["status"]
            connection.execute(
                "UPDATE scans SET status=?,document=? WHERE id=?",
                (status, safe_document(document), run_id),
            )
        return self.get(run_id)

    @staticmethod
    def decode(row: sqlite3.Row) -> dict[str, Any]:
        return {
            **json.loads(row["document"]),
            **{k: row[k] for k in ("id", "site_id", "started", "completed", "status")},
        }

    def get(self, run_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM scans WHERE id=?", (run_id,)).fetchone()
            if row is None:
                raise KeyError("Unknown scan")
            return self.decode(row)

    def latest(self, site_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM scans WHERE site_id=? ORDER BY started DESC,rowid DESC LIMIT 1",
                (site_id,),
            ).fetchone()
            return self.decode(row) if row else None

    def scans(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            return [
                self.decode(row)
                for row in connection.execute("SELECT * FROM scans ORDER BY started,rowid")
            ]

    def site_status(self, site_id: str) -> dict[str, Any]:
        rows = [r for r in self.scans() if r["site_id"] == site_id]
        return {
            "current": rows[-1]["status"] if rows else "never",
            "last_success": next(
                (r["completed"] for r in reversed(rows) if r["status"] == "complete"), None
            ),
            "last_failed": next(
                (
                    r["completed"]
                    for r in reversed(rows)
                    if r["status"] in {"failed", "partial", "interrupted"}
                ),
                None,
            ),
        }

    def acquire(self, key: str, owner: str, now: datetime, duration: timedelta) -> bool:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT expires FROM leases WHERE key=?", (key,)).fetchone()
            if row and datetime.fromisoformat(row[0]) > now:
                return False
            connection.execute(
                "INSERT OR REPLACE INTO leases VALUES (?,?,?)",
                (key, owner, (now + duration).astimezone(UTC).isoformat()),
            )
        return True

    def release(self, key: str, owner: str) -> bool:
        with self.connect() as connection:
            return bool(
                connection.execute(
                    "DELETE FROM leases WHERE key=? AND owner=?", (key, owner)
                ).rowcount
            )

    def recover(self, now: datetime, age: timedelta) -> int:
        with self.connect() as connection:
            return connection.execute(
                "UPDATE scans SET status='interrupted',completed=? WHERE status='running' AND started<?",
                (now.isoformat(), (now - age).astimezone(UTC).isoformat()),
            ).rowcount

    def backup(self, target: Path) -> None:
        with self.connect() as source, sqlite3.connect(target) as destination:
            source.backup(destination)
        target.chmod(0o600)

    def save_feed(self, feed: FeedSnapshot) -> None:
        from dataclasses import asdict

        if not feed.records or len(feed.records) > 100_000 or feed.fetched_at.tzinfo is None:
            raise FeedError("cache_validation")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM intelligence")
            for record in feed.records:
                data = asdict(record)
                data["software"] = list(data["software"])
                data["references"] = list(data["references"])
                for field in ("published", "updated"):
                    data[field] = data[field].isoformat() if data[field] else None
                connection.execute(
                    "INSERT INTO intelligence VALUES (?,?)", (record.id, safe_document(data))
                )
            connection.execute(
                "INSERT OR REPLACE INTO feed_meta VALUES (1,?,?,?)",
                (feed.fetched_at.isoformat(), feed.source, len(feed.records)),
            )

    def load_feed(self) -> FeedSnapshot | None:
        with self.connect() as connection:
            meta = connection.execute("SELECT * FROM feed_meta WHERE singleton=1").fetchone()
            if meta is None:
                return None
            records = []
            try:
                for row in connection.execute("SELECT record FROM intelligence ORDER BY rowid"):
                    raw = json.loads(row[0])
                    raw["software"] = tuple(raw["software"])
                    raw["references"] = tuple(raw["references"])
                    raw["published"] = parsed_date(raw["published"])
                    raw["updated"] = parsed_date(raw["updated"])
                    records.append(Record(**raw))
                captured = parsed_date(meta["fetched_at"])
                if captured is None or len(records) != meta["count"] or not records:
                    raise ValueError("Invalid cache")
                return FeedSnapshot(tuple(records), captured, meta["source"])
            except (ValueError, KeyError, TypeError):
                raise FeedError("cache_validation") from None
