from datetime import UTC, datetime

import httpx
import pytest
from pydantic import ValidationError

from sentinel_audit.config import SiteConfig
from sentinel_audit.history import Store
from sentinel_audit.inventory import InventoryError, parse_inventory
from sentinel_audit.runner import run_audits
from sentinel_audit.transport import GuardedClient
from sentinel_audit.wordfence import FeedSnapshot


def site(**changes):
    return SiteConfig(
        id="fixture",
        name="Fixture",
        production_url="https://audit.example.org",
        authorized=True,
        methods=["inventory"],
        connector_token_env="SENTINEL_FIXTURE_TOKEN",
        **changes,
    )


def payload():
    return {
        "schema": "sentinel-inventory/v1",
        "generatedAt": datetime.now(UTC).isoformat(),
        "site": {"url": "https://audit.example.org", "name": "Fixture"},
        "components": [
            {
                "id": "core",
                "type": "core",
                "name": "WordPress",
                "slug": "wordpress",
                "version": "6.9",
                "status": "runtime",
            }
        ],
        "updatesCheckedAt": {"core": "invalid"},
    }


def test_reporting_timezone_rejects_unknown_zone():
    with pytest.raises(ValidationError):
        site(reporting={"timezone": "No/Such_Zone"})


def test_update_timestamps_must_be_valid_aware_and_not_future():
    with pytest.raises(InventoryError):
        parse_inventory(payload(), "https://audit.example.org")


def test_remote_credential_echo_redacted_before_database_and_exports(tmp_path):
    from sentinel_audit.config import AuditConfig

    token = "Z" * 64
    raw = payload()
    raw["updatesCheckedAt"] = {}
    raw["components"][0]["name"] = "Echo " + token

    def factory(s, c):
        return GuardedClient(
            s,
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=raw)),
            sleep=lambda _: None,
            cancel=c,
        )

    store = Store(tmp_path / "db")
    run_audits(
        AuditConfig(sites=[site()]),
        store,
        tmp_path / "out",
        environment={"SENTINEL_FIXTURE_TOKEN": token},
        client_factory=factory,
    )
    assert token not in repr(store.latest("fixture"))
    assert token not in (tmp_path / "out" / "fixture.json").read_text()


def test_successful_feed_persisted_for_history_source_provenance(tmp_path):
    from sentinel_audit.config import AuditConfig
    from sentinel_audit.wordfence import parse_record

    record = parse_record(
        {
            "id": "fixture",
            "title": "TEST",
            "software": [{"type": "core", "slug": "wordpress", "affected_versions": {}}],
            "copyrights": {"notice": "retain"},
        }
    )
    feed = FeedSnapshot((record,), datetime.now(UTC))
    store = Store(tmp_path / "db")
    run_audits(AuditConfig(sites=[]), store, tmp_path / "out", environment={}, feed=feed)
    assert store.load_feed() == feed
