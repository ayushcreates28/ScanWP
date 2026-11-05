"""Wordfence v3 normalized feed records and bounded, authenticated retrieval."""

from __future__ import annotations

import json
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import httpcore
import httpx
import ijson
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr, ValidationError

from .transport import PinnedTransport, ScopeError

ENDPOINT = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"


class FeedError(ValueError):
    def __init__(self, kind: str) -> None:
        self.kind = kind
        super().__init__("Vulnerability feed unavailable: " + kind)


class Range(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    from_version: StrictStr = Field(max_length=100)
    from_inclusive: StrictBool
    to_version: StrictStr = Field(max_length=100)
    to_inclusive: StrictBool


class Software(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    type: StrictStr = Field(pattern="^(core|plugin|theme)$")
    slug: StrictStr = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,149}$")
    name: StrictStr | None = Field(default=None, max_length=250)
    affected_versions: dict[str, Range]
    patched_versions: list[StrictStr] = Field(default=[], max_length=100)
    remediation: StrictStr | None = Field(default=None, max_length=20_000)


@dataclass(frozen=True)
class Record:
    id: str
    title: str
    software: tuple[dict[str, Any], ...]
    score: float | None
    published_severity: str | None
    cve: str | None
    references: tuple[str, ...]
    published: datetime | None
    updated: datetime | None
    copyrights: dict[str, Any]


def parsed_date(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value)
        return result.replace(tzinfo=UTC) if result.tzinfo is None else result.astimezone(UTC)
    except ValueError:
        return None


def safe_reference(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or len(value) > 2048
        or any(c.isspace() or ord(c) < 32 for c in value)
    ):
        return False
    try:
        url = urlsplit(value)
        return (
            url.scheme in {"https", "http"}
            and bool(url.hostname)
            and url.username is None
            and url.password is None
        )
    except ValueError:
        return False


def parse_record(raw: Any) -> Record:
    if (
        not isinstance(raw, dict)
        or not isinstance(raw.get("id"), str)
        or not raw["id"]
        or len(raw["id"]) > 120
        or not isinstance(raw.get("title"), str)
        or len(raw["title"]) > 1000
        or not isinstance(raw.get("software"), list)
        or not raw["software"]
    ):
        raise FeedError("schema")
    if len(json.dumps(raw, default=str)) > 128_000 or len(raw["software"]) > 100:
        raise FeedError("schema")
    try:
        software = tuple(Software.model_validate(s).model_dump() for s in raw["software"])
    except ValidationError:
        raise FeedError("schema") from None
    raw_cvss = raw.get("cvss")
    cvss = raw_cvss if isinstance(raw_cvss, dict) else {}
    number = cvss.get("score")
    try:
        score = float(number) if number is not None and not isinstance(number, bool) else None
    except (ValueError, TypeError):
        score = None
    if score is not None and not 0 <= score <= 10:
        score = None
    rating = str(cvss.get("rating", "")).lower()
    severity = rating if rating in {"critical", "high", "medium", "low", "informational"} else None
    raw_refs = raw.get("references")
    refs = raw_refs if isinstance(raw_refs, list) else []
    raw_copyrights = raw.get("copyrights")
    copyrights = raw_copyrights if isinstance(raw_copyrights, dict) else {}
    cve = raw.get("cve") if isinstance(raw.get("cve"), str) else None
    return Record(
        raw["id"],
        raw["title"],
        software,
        score,
        severity,
        cve,
        tuple(r for r in refs if safe_reference(r)),
        parsed_date(raw.get("published")),
        parsed_date(raw.get("updated")),
        copyrights,
    )


@dataclass(frozen=True)
class FeedSnapshot:
    records: tuple[Record, ...]
    fetched_at: datetime
    source: str = ENDPOINT

    def is_stale(self, now: datetime, max_age: timedelta = timedelta(hours=24)) -> bool:
        return now - self.fetched_at > max_age or self.fetched_at - now > timedelta(minutes=5)


class WordfenceClient:
    def __init__(
        self,
        api_key: str,
        terms_accepted: bool = False,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        max_bytes: int = 300_000_000,
        max_records: int = 100_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._api_key = api_key
        self.terms_accepted = terms_accepted
        self.transport = transport
        self.sleep = sleep
        self.max_bytes = max_bytes
        self.max_records = max_records
        self.clock = clock

    def fetch(self) -> FeedSnapshot:
        if not self.terms_accepted:
            raise FeedError("terms_not_acknowledged")
        if (
            not self._api_key
            or len(self._api_key) > 1024
            or any(c.isspace() or ord(c) < 32 for c in self._api_key)
        ):
            raise FeedError("credentials")
        deadline = self.clock() + 180
        with httpx.Client(
            transport=self.transport or PinnedTransport(frozenset({"www.wordfence.com"})),
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(30, connect=15),
        ) as client:
            for attempt in range(3):
                try:
                    with client.stream(
                        "GET",
                        ENDPOINT,
                        headers={
                            "Authorization": "Bearer " + self._api_key,
                            "Accept": "application/json",
                            "Accept-Encoding": "identity",
                        },
                    ) as response:
                        status = response.status_code
                        if status in {401, 403}:
                            raise FeedError("authentication")
                        if status == 429 or status >= 500:
                            if attempt < 2:
                                self.sleep(min(5.0, 0.5 * 2**attempt))
                                continue
                            raise FeedError("rate_limit" if status == 429 else "http")
                        if status != 200:
                            raise FeedError("http")
                        if response.headers.get("content-encoding", "identity").lower() not in {
                            "identity",
                            "",
                        }:
                            raise FeedError("encoding")
                        with tempfile.TemporaryFile(mode="w+b") as target:
                            size = 0
                            for chunk in response.iter_bytes(chunk_size=65536):
                                size += len(chunk)
                                if size > self.max_bytes:
                                    raise FeedError("size")
                                if self.clock() > deadline:
                                    raise FeedError("timeout")
                                target.write(chunk)
                            target.seek(0)
                            records: dict[str, Record] = {}
                            try:
                                for key, raw in ijson.kvitems(target, ""):
                                    if self.clock() > deadline:
                                        raise FeedError("timeout")
                                    record = parse_record(raw)
                                    if record.id != key or (
                                        key in records and record != records[key]
                                    ):
                                        raise FeedError("schema")
                                    records[key] = record
                                    if len(records) > self.max_records:
                                        raise FeedError("size")
                            except FeedError:
                                raise
                            except (ijson.JSONError, ValueError, TypeError):
                                raise FeedError("schema") from None
                            if not records:
                                raise FeedError("empty_feed")
                            return FeedSnapshot(tuple(records.values()), datetime.now(UTC))
                except (
                    httpx.TransportError,
                    httpcore.NetworkError,
                    httpcore.TimeoutException,
                    httpcore.ProtocolError,
                    ScopeError,
                    OSError,
                ):
                    if attempt < 2:
                        self.sleep(0.5 * 2**attempt)
                        continue
                    raise FeedError("network") from None
        raise FeedError("http")
