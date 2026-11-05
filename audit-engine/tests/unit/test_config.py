"""Tests precede configuration implementation; see evidence/m01-red.log."""

import json

import pytest
from pydantic import ValidationError

from sentinel_audit.config import AuditConfig, SiteConfig, load_config, normalize_url


def site(**changes):
    return {
        "id": "quadigy",
        "name": "Quadigy",
        "production_url": "https://www.quadigy.com/",
        "authorized": True,
        "methods": ["public"],
        **changes,
    }


@pytest.mark.parametrize("value", ["https://example.org", "https://EXAMPLE.org/blog/"])
def test_normalizes_authorized_url(value):
    assert normalize_url(value).startswith("https://example.org")


@pytest.mark.parametrize(
    "value",
    [
        "example.org",
        "ftp://example.org",
        "https://user:pass@example.org",
        "http://127.0.0.1",
        "https://[::1]",
        "http://2130706433",
        "https://0x7f000001",
        "https://host.local",
        "https://localhost",
        "https://x.internal",
        "https://example.org:8443",
        "https://example.org/?secret=token",
        "https://example.org/#x",
        "https://example.org/%2e%2e/admin",
        "https://example.org/../admin",
        "https://example.org\\@evil.org",
        "https://example.org.\n",
        "https://example.org.",
    ],
)
def test_rejects_unsafe_urls(value):
    with pytest.raises(ValueError):
        normalize_url(value)


def test_authorization_is_explicit_and_strict():
    for value in [False, "true", 1, None]:
        with pytest.raises((ValueError, ValidationError)):
            SiteConfig.model_validate(site(authorized=value))
    with pytest.raises(ValidationError):
        SiteConfig.model_validate({k: v for k, v in site().items() if k != "authorized"})


def test_defaults_and_secret_references():
    s = SiteConfig.model_validate(site())
    assert s.rate_limit_per_second <= 1
    assert s.timeout_seconds <= 30
    assert s.enabled
    assert s.connector_token_env is None
    s = SiteConfig.model_validate(
        site(methods=["inventory"], connector_token_env="SENTINEL_QUADIGY_TOKEN")
    )
    assert "actual-secret" not in s.model_dump_json()


@pytest.mark.parametrize(
    "changes",
    [
        {"id": "../bad"},
        {"methods": ["exploit"]},
        {"methods": []},
        {"connector_token_env": "actual-secret-token"},
        {"api_token": "a secret"},
        {"rate_limit_per_second": 0},
        {"rate_limit_per_second": 1000},
        {"timeout_seconds": 0},
        {"environment": "unknown"},
    ],
)
def test_invalid_configuration_is_rejected(changes):
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(site(**changes))


def test_authenticated_inventory_requires_https_and_secret_reference():
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(site(methods=["inventory"]))
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(
            site(
                production_url="http://example.org",
                methods=["inventory"],
                connector_token_env="SENTINEL_TEST_TOKEN",
            )
        )


def test_registry_rejects_duplicate_ids_and_hosts():
    for second in [
        site(),
        site(id="other"),
        site(id="other", production_url="https://www.quadigy.com/another/"),
    ]:
        with pytest.raises(ValidationError):
            AuditConfig.model_validate({"sites": [site(), second]})


def test_staging_requires_explicit_authorization():
    with pytest.raises(ValidationError):
        SiteConfig.model_validate(site(staging_url="https://staging.quadigy.com/"))
    s = SiteConfig.model_validate(
        site(staging_url="https://staging.quadigy.com/", staging_authorized=True)
    )
    assert s.staging_url == "https://staging.quadigy.com/"


def test_configuration_loads_without_source_edits(tmp_path):
    path = tmp_path / "sites.json"
    path.write_text(json.dumps({"sites": [site()]}), encoding="utf-8")
    config = load_config(path)
    assert config.sites[0].id == "quadigy"
    assert config.schedule.day == 1
    assert config.schedule.hour == 9
    assert config.schedule.minute == 17
    assert config.schedule.timezone == "Asia/Kolkata"
    path.write_text(json.dumps({"sites": [site(enabled=False)]}), encoding="utf-8")
    assert not load_config(path).sites[0].enabled


@pytest.mark.parametrize(
    "schedule", [{"timezone": "No/Such_Zone"}, {"day": 32}, {"hour": 24}, {"minute": 60}]
)
def test_invalid_schedule_is_rejected(schedule):
    with pytest.raises(ValidationError):
        AuditConfig.model_validate({"sites": [site()], "schedule": schedule})
