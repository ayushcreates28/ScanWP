from datetime import UTC, datetime, timedelta

import httpx
import pytest

from sentinel_audit.config import AuditConfig, SiteConfig
from sentinel_audit.history import Store
from sentinel_audit.runner import run_audits
from sentinel_audit.transport import GuardedClient
from sentinel_audit.wordfence import FeedSnapshot, parse_record


def site(key="fixture", **changes):
    return SiteConfig(
        id=key,
        name="TEST " + key,
        production_url=f"https://{key}.example.org",
        authorized=True,
        methods=["inventory"],
        connector_token_env="SENTINEL_TOKEN_FIXTURE",
        **changes,
    )


def inventory(version="1.0"):
    return {
        "schema": "sentinel-inventory/v1",
        "generatedAt": datetime.now(UTC).isoformat(),
        "site": {"url": "https://fixture.example.org/", "name": "TEST DATA"},
        "components": [
            {
                "id": "core",
                "type": "core",
                "slug": "wordpress",
                "name": "WordPress",
                "version": "6.9",
                "status": "runtime",
                "updateState": "current",
            },
            {
                "id": "fixture-plugin",
                "type": "plugin",
                "slug": "fixture",
                "name": "Fixture",
                "version": version,
                "status": "active",
                "slugSource": "wordpress.org",
                "updateState": "available" if version == "1.0" else "current",
                "latest": "2.0",
            },
        ],
        "updatesCheckedAt": {
            "plugins": datetime.now(UTC).isoformat(),
            "core": datetime.now(UTC).isoformat(),
        },
        "settings": {
            "debug": False,
            "debugDisplay": False,
            "fileEditorDisabled": True,
            "forceSSLAdmin": True,
            "phpSecuritySupported": True,
            "registrationEnabled": False,
        },
    }


def feed(age=0):
    raw = {
        "id": "test-advisory",
        "title": "TEST DATA advisory",
        "software": [
            {
                "type": "plugin",
                "slug": "fixture",
                "affected_versions": {
                    "<=1": {
                        "from_version": "*",
                        "from_inclusive": True,
                        "to_version": "1.0",
                        "to_inclusive": True,
                    }
                },
                "patched_versions": ["2.0"],
            }
        ],
        "cvss": {"score": 9.1, "rating": "critical"},
        "copyrights": {"fixture": "TEST LICENSE"},
    }
    return FeedSnapshot((parse_record(raw),), datetime.now(UTC) - timedelta(hours=age))


def factory(payload=None, status=200):
    return lambda s, cancel: GuardedClient(
        s,
        transport=httpx.MockTransport(
            lambda _: httpx.Response(status, json=payload or inventory())
        ),
        sleep=lambda _: None,
        cancel=cancel,
    )


@pytest.mark.e2e
def test_two_months_inventory_matching_history_reports_and_failure_isolation(tmp_path):
    store = Store(tmp_path / "db")
    config = AuditConfig(sites=[site(), site("failure")])
    env = {"SENTINEL_TOKEN_FIXTURE": "a" * 64}

    def clients(s, cancel):
        return factory(status=403 if s.id == "failure" else 200)(s, cancel)

    first = run_audits(
        config, store, tmp_path / "one", environment=env, feed=feed(), client_factory=clients
    )
    assert first["status"] == "partial"
    good = store.latest("fixture")
    assert good["status"] == "complete"
    assert any(
        f["advisory_id"] == "test-advisory" and f["status"] == "open" for f in good["findings"]
    )
    assert store.latest("failure")["status"] == "failed"
    second = run_audits(
        AuditConfig(sites=[site()]),
        store,
        tmp_path / "two",
        environment=env,
        feed=feed(),
        client_factory=factory(inventory("2.0")),
    )
    assert second["status"] == "complete"
    good = store.latest("fixture")
    assert any(
        c["change"] == "resolved" and c["previous"]["advisory_id"] == "test-advisory"
        for c in good["changes"]
    )
    assert (tmp_path / "two" / "consolidated.pdf").exists()
    assert "TEST LICENSE" in (tmp_path / "one" / "fixture.json").read_text()
    assert "a" * 64 not in (tmp_path / "one" / "consolidated.json").read_text()


@pytest.mark.parametrize("feed_value", [None, 36])
def test_missing_or_stale_intelligence_never_clears_previous_finding(tmp_path, feed_value):
    store = Store(tmp_path / "db")
    config = AuditConfig(sites=[site()])
    env = {"SENTINEL_TOKEN_FIXTURE": "a" * 64}
    run_audits(
        config, store, tmp_path / "one", environment=env, feed=feed(), client_factory=factory()
    )
    run_audits(
        config,
        store,
        tmp_path / "two",
        environment=env,
        feed=None if feed_value is None else feed(feed_value),
        client_factory=factory(inventory("2.0")),
    )
    latest = store.latest("fixture")
    assert latest["status"] == "partial"
    assert not any(
        c["change"] == "resolved" and c["previous"]["advisory_id"] == "test-advisory"
        for c in latest["changes"]
    )


def test_cancellation_disabled_sites_and_overlap(tmp_path):
    store = Store(tmp_path / "db")
    config = AuditConfig(sites=[site(), site("disabled", enabled=False)])
    result = run_audits(
        config, store, tmp_path / "cancel", environment={}, feed=feed(), cancel=lambda: True
    )
    assert result["status"] == "partial"
    assert store.latest("fixture")["status"] == "cancelled"
    assert store.latest("disabled")["status"] == "skipped"
    assert store.acquire("audit-run", "other", datetime.now(UTC), timedelta(hours=1))
    assert run_audits(config, store, tmp_path / "locked", environment={})["status"] == "overlap"


def test_unexpected_site_failure_is_redacted_and_other_sites_continue(tmp_path):
    store = Store(tmp_path / "db")

    def explode(s, cancel):
        raise RuntimeError("secret-api-key")

    result = run_audits(
        AuditConfig(sites=[site(), site("other")]),
        store,
        tmp_path / "errors",
        environment={},
        client_factory=explode,
    )
    assert len(result["scans"]) == 2
    assert all(s["status"] == "failed" for s in result["scans"])
    assert "secret-api-key" not in (tmp_path / "errors" / "consolidated.json").read_text()


def test_approved_offline_inventory_and_integrity_baselines(tmp_path):
    config = AuditConfig(
        sites=[
            SiteConfig(
                id="fixture",
                name="TEST",
                production_url="https://fixture.example.org",
                authorized=True,
                methods=["wpcli", "integrity"],
            )
        ]
    )
    store = Store(tmp_path / "db")
    manifest = {"files": {"wp-includes/file.php": {"sha256": "a" * 64}}, "complete": True}
    first = run_audits(
        config,
        store,
        tmp_path / "one",
        environment={},
        feed=feed(),
        client_factory=factory(),
        offline_inventories={"fixture": inventory()},
        integrity_manifests={"fixture": manifest},
    )
    assert first["scans"][0]["integrity"][0]["state"] == "new"
    second = run_audits(
        config,
        store,
        tmp_path / "two",
        environment={},
        feed=feed(),
        client_factory=factory(),
        offline_inventories={"fixture": inventory()},
        integrity_manifests={"fixture": manifest},
    )
    assert second["scans"][0]["integrity"][0]["state"] == "unchanged"
    manifest["trusted_reference"] = manifest["files"]
    third = run_audits(
        config,
        store,
        tmp_path / "three",
        environment={},
        feed=feed(),
        client_factory=factory(),
        offline_inventories={"fixture": inventory()},
        integrity_manifests={"fixture": manifest},
    )
    assert third["scans"][0]["integrity"][0]["state"] == "known-clean"


def test_missing_offline_data_and_integrity_fail_visibly(tmp_path):
    config = AuditConfig(
        sites=[
            SiteConfig(
                id="fixture",
                name="TEST",
                production_url="https://fixture.example.org",
                authorized=True,
                methods=["wpcli", "integrity"],
            )
        ]
    )
    result = run_audits(
        config, Store(tmp_path / "db"), tmp_path / "out", environment={}, client_factory=factory()
    )
    assert result["status"] == "partial"
    assert any("integrity" in text for text in result["scans"][0]["limitations"])


def test_public_only_scan_cannot_claim_full_inventory_audit(tmp_path):
    config = AuditConfig(
        sites=[
            SiteConfig(
                id="fixture",
                name="TEST",
                production_url="https://fixture.example.org",
                authorized=True,
                methods=["public"],
            )
        ]
    )
    result = run_audits(
        config, Store(tmp_path / "db"), tmp_path / "out", environment={}, client_factory=factory()
    )
    assert result["scans"][0]["status"] == "partial"
    assert result["scans"][0]["checks"]


def test_one_site_report_failure_sets_batch_alert(tmp_path, monkeypatch):
    import sentinel_audit.runner as module

    original = module.export_report

    def fail_one(report, output, stem):
        if stem == "fixture":
            raise OSError("fixture report unavailable")
        return original(report, output, stem)

    monkeypatch.setattr(module, "export_report", fail_one)
    result = run_audits(
        AuditConfig(sites=[site()]),
        Store(tmp_path / "db"),
        tmp_path / "out",
        environment={"SENTINEL_TOKEN_FIXTURE": "a" * 64},
        feed=feed(),
        client_factory=factory(),
    )
    assert any(a["status"] == "report_failed" for a in result["alerts"])
    assert result["status"] == "partial"
