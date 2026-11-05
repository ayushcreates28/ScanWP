from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from sentinel_audit.history import Store, canonicalize, compare_findings


def finding(key="test", status="open", **extra):
    return {
        "id": key,
        "status": status,
        "title": "Fixture finding",
        "priority": "high",
        "category": "configuration",
        "evidence": "Confirmed fixture",
        "confidence": "confirmed",
        "references": [],
        **extra,
    }


@pytest.mark.parametrize(
    "current,previous,expected",
    [
        ([finding()], [], "new"),
        ([finding()], [finding()], "recurring"),
        ([finding(status="clear")], [finding()], "resolved"),
        ([finding(status="unknown")], [finding()], "verification"),
        ([], [finding()], "not_comparable"),
        ([finding()], [finding(status="clear")], "new"),
    ],
)
def test_history_requires_explicit_clear_observation(current, previous, expected):
    assert compare_findings(current, previous)[0]["change"] == expected


def test_duplicate_findings_deduplicated_and_conflicts_rejected():
    assert len(canonicalize([finding(), finding()])) == 1
    with pytest.raises(ValueError):
        canonicalize([finding(), finding(status="clear")])


@pytest.mark.parametrize(
    "bad",
    [
        {"password": "secret"},
        {"details": {"Authorization": "Bearer secret"}},
        {"references": ["javascript:alert(1)"]},
        {"id": "../escape"},
        {"status": "clean"},
        {"cvss": 11},
    ],
)
def test_canonical_input_rejects_unsafe_or_invented_data(bad):
    with pytest.raises(ValueError):
        canonicalize([finding(**bad)])


@pytest.mark.integration
def test_sqlite_history_transactions_and_site_isolation(tmp_path):
    store = Store(tmp_path / "history.db")
    first = store.begin("site-one", datetime(2026, 1, 1, tzinfo=UTC))
    store.finish(first, "complete", {"findings": [finding("sql'-input")], "checks": []})
    second = store.begin("site-two", datetime(2026, 1, 1, tzinfo=UTC))
    store.finish(second, "failed", {"findings": [], "error": "authentication"})
    assert store.latest("site-one")["findings"][0]["id"] == "sql'-input"
    assert store.latest("site-two")["status"] == "failed"
    assert store.site_status("site-one")["last_success"] is not None
    assert store.site_status("site-two")["last_failed"] is not None
    assert len(store.scans()) == 2
    with pytest.raises(ValueError):
        store.finish(first, "complete", {"findings": []})
    assert Store(tmp_path / "history.db").latest("site-one")["id"] == first


def test_concurrent_writes_and_atomic_leases(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    now = datetime.now(UTC)
    with ThreadPoolExecutor(max_workers=4) as pool:
        ids = list(pool.map(lambda n: store.begin("site-" + str(n), now), range(8)))
        acquired = list(
            pool.map(
                lambda n: store.acquire("monthly", "owner-" + str(n), now, timedelta(minutes=1)),
                range(8),
            )
        )
    assert len(set(ids)) == 8
    assert sum(acquired) == 1
    assert store.acquire("monthly", "replacement", now + timedelta(minutes=2), timedelta(minutes=1))
    assert not store.release("monthly", "wrong-owner")
    assert store.release("monthly", "replacement")
    assert store.recover(now + timedelta(hours=1), timedelta(minutes=30)) == 8
    assert all(s["status"] == "interrupted" for s in store.scans())


def test_corrupt_database_reports_error(tmp_path):
    path = tmp_path / "corrupt"
    path.write_bytes(b"not sqlite")
    import sqlite3

    with pytest.raises(sqlite3.DatabaseError):
        Store(path)


def test_connections_are_closed_after_transactions(tmp_path):
    import sqlite3

    store = Store(tmp_path / "closed.db")
    with store.connect() as connection:
        connection.execute("SELECT 1")
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")


def test_feed_cache_atomic_storage_and_license_roundtrip(tmp_path):
    from sentinel_audit.wordfence import FeedError, FeedSnapshot, parse_record

    raw = {
        "id": "fixture-advisory",
        "title": "Fixture",
        "software": [{"type": "plugin", "slug": "fixture", "affected_versions": {}}],
        "copyrights": {"notice": "Retain fixture notice"},
    }
    store = Store(tmp_path / "feed.db")
    assert store.load_feed() is None
    feed = FeedSnapshot((parse_record(raw),), datetime.now(UTC))
    store.save_feed(feed)
    assert store.load_feed() == feed
    with pytest.raises(FeedError):
        store.save_feed(FeedSnapshot((), datetime.now(UTC)))
    assert store.load_feed() == feed


def test_report_failure_preserves_findings_and_requires_terminal_scan(tmp_path):
    store = Store(tmp_path / "report.db")
    run = store.begin("fixture", datetime.now(UTC))
    with pytest.raises(ValueError):
        store.report_failed(run)
    with pytest.raises(ValueError):
        store.report_failed("unknown")
    before = store.finish(run, "complete", {"findings": [finding()]})
    after = store.report_failed(run)
    assert after["status"] == "partial" and after["report_status"] == "failed"
    assert after["findings"] == before["findings"]
    assert after["completed"] == before["completed"]
