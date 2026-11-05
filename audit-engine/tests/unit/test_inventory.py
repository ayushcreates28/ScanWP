from datetime import UTC, datetime

import httpx
import pytest

from sentinel_audit.config import SiteConfig
from sentinel_audit.inventory import InventoryError, fetch_inventory, parse_inventory, parse_wpcli
from sentinel_audit.transport import GuardedClient


def snapshot(**changes):
    return {
        "schema": "sentinel-inventory/v1",
        "generatedAt": datetime.now(UTC).isoformat(),
        "site": {"url": "https://audit.example.org/", "name": "Fixture", "multisite": False},
        "components": [
            {
                "id": "core",
                "type": "core",
                "name": "WordPress",
                "slug": "wordpress",
                "version": "6.9.1",
                "status": "runtime",
                "updateState": "current",
            },
            {
                "id": "php",
                "type": "php",
                "name": "PHP",
                "slug": "php",
                "version": "8.4.1",
                "status": "runtime",
                "updateState": "unknown",
            },
            {
                "id": "p:fixture",
                "type": "plugin",
                "name": "Fixture",
                "slug": "fixture",
                "version": "1.2-rc1",
                "status": "inactive",
                "updateState": "available",
                "latest": "1.3",
                "autoUpdate": True,
            },
        ],
        "settings": {"debug": False},
        "updatesCheckedAt": {},
        **changes,
    }


def test_parse_inventory_preserves_states_and_unusual_versions_and_discards_unknown_secrets():
    data = snapshot(password="do-not-store")
    data["settings"]["DB_PASSWORD"] = "do-not-store"
    result = parse_inventory(data, "https://audit.example.org/")
    assert result["components"][2]["version"] == "1.2-rc1"
    assert result["components"][2]["status"] == "inactive"
    assert result["components"][2]["update_state"] == "available"
    assert result["core_version"] == "6.9.1"
    assert "do-not-store" not in repr(result)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(components=[]),
        lambda d: d.update(generatedAt="yesterday"),
        lambda d: d.update(schema="other"),
        lambda d: d["components"].append(d["components"][0]),
        lambda d: d["components"][2].update(version={"password": "secret"}),
        lambda d: d["site"].update(url="https://other.example.org/"),
    ],
)
def test_invalid_inventory_is_not_silently_clean(mutate):
    data = snapshot()
    mutate(data)
    with pytest.raises(InventoryError):
        parse_inventory(data, "https://audit.example.org/")


def configured():
    return SiteConfig.model_validate(
        {
            "id": "fixture",
            "name": "Fixture",
            "production_url": "https://audit.example.org/",
            "authorized": True,
            "methods": ["inventory"],
            "connector_token_env": "SENTINEL_FIXTURE_TOKEN",
        }
    )


@pytest.mark.integration
def test_authenticated_connector_to_inventory_parser():
    requests = []

    def handler(r):
        requests.append(r)
        return httpx.Response(200, json=snapshot())

    with GuardedClient(
        configured(), transport=httpx.MockTransport(handler), sleep=lambda _: None
    ) as client:
        result = fetch_inventory(client, {"SENTINEL_FIXTURE_TOKEN": "fixture-token"})
    assert result["status"] == "complete"
    assert requests[0].headers["Authorization"] == "Bearer fixture-token"
    assert requests[0].url.path == "/wp-json/sentinel-audit/v1/inventory"
    assert "fixture-token" not in repr(result)


@pytest.mark.integration
@pytest.mark.parametrize(
    "status,error",
    [
        (401, "authentication"),
        (403, "authentication"),
        (404, "endpoint"),
        (429, "http"),
        (500, "http"),
    ],
)
def test_connector_errors_are_explicit(status, error):
    with GuardedClient(
        configured(),
        transport=httpx.MockTransport(lambda _: httpx.Response(status)),
        sleep=lambda _: None,
    ) as client:
        r = fetch_inventory(client, {"SENTINEL_FIXTURE_TOKEN": "fixture-token"})
    assert r["status"] == "failed" and r["error"] == error


@pytest.mark.security
def test_missing_secret_and_disabled_method_do_not_send_network_requests():
    with GuardedClient(
        configured(), transport=httpx.MockTransport(lambda _: pytest.fail("no request"))
    ) as client:
        r = fetch_inventory(client, {})
    assert r["error"] == "credentials"
    site = configured().model_copy(update={"methods": ["public"]})
    with GuardedClient(
        site, transport=httpx.MockTransport(lambda _: pytest.fail("no request"))
    ) as client:
        r = fetch_inventory(client, {})
    assert r["status"] == "skipped"


def test_malformed_connector_json_never_echoes_raw_payload():
    with GuardedClient(
        configured(),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, text="do-not-echo-secret")),
        sleep=lambda _: None,
    ) as client:
        r = fetch_inventory(client, {"SENTINEL_FIXTURE_TOKEN": "fixture-token"})
    assert r["status"] == "failed" and "do-not-echo-secret" not in repr(r)


def test_wpcli_adapter_handles_inactive_mu_and_network_plugin_states():
    r = parse_wpcli(
        "6.9.1",
        [
            {"name": "fixture", "status": "must-use", "version": "1.0", "update": "none"},
            {
                "name": "other",
                "status": "active-network",
                "version": "2",
                "update": "available",
                "update_version": "2.1",
            },
        ],
        [{"name": "theme", "status": "active", "version": "1", "update": "none"}],
        "https://audit.example.org/",
    )
    assert r["components"][1]["status"] == "must-use"
    assert r["components"][2]["status"] == "network-active"
    assert r["components"][2]["update_state"] == "available"


@pytest.mark.security
def test_connector_rejects_header_injection_without_request():
    with GuardedClient(
        configured(), transport=httpx.MockTransport(lambda _: pytest.fail("no request"))
    ) as client:
        r = fetch_inventory(client, {"SENTINEL_FIXTURE_TOKEN": "fixture\r\nInjected: yes"})
    assert r["error"] == "credentials"


def test_wpcli_does_not_fabricate_inactive_status_for_unrecognized_state():
    r = parse_wpcli(
        "6.9",
        [{"name": "custom", "status": "unexpected", "version": "1"}],
        [],
        "https://audit.example.org/",
    )
    assert r["components"][1]["status"] == "unknown"


def test_wpcli_malformed_records_raise_inventory_error():
    with pytest.raises(InventoryError):
        parse_wpcli("6.9", [None], [], "https://audit.example.org/")
