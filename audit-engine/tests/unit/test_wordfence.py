from datetime import UTC, datetime, timedelta

import httpx
import pytest

from sentinel_audit.matching import compare_versions, internal_priority, match_advisory
from sentinel_audit.wordfence import FeedError, WordfenceClient, parse_record


def raw(**changes):
    return {
        "id": "fixture-001",
        "title": "Synthetic test advisory",
        "software": [
            {
                "type": "plugin",
                "slug": "fixture",
                "name": "Fixture",
                "affected_versions": {
                    "branch-a": {
                        "from_version": "1.0",
                        "from_inclusive": True,
                        "to_version": "1.2.3",
                        "to_inclusive": True,
                    },
                    "branch-b": {
                        "from_version": "2.0",
                        "from_inclusive": True,
                        "to_version": "2.0.1",
                        "to_inclusive": False,
                    },
                },
                "patched": True,
                "patched_versions": ["1.2.4", "2.0.1"],
            }
        ],
        "cvss": {"score": 9.8, "rating": "Critical"},
        "cve": "CVE-2026-12345",
        "references": ["https://www.wordfence.com/threat-intel/vulnerabilities/example"],
        "published": "2026-10-01 00:00:00",
        "updated": "2026-11-01 00:00:00",
        "copyrights": {
            "message": "Synthetic fixture, not provider data",
            "fixture": {
                "notice": "Fixture authors",
                "license": "Synthetic test license",
                "license_url": "https://example.org/license",
            },
        },
        **changes,
    }


@pytest.mark.parametrize(
    "left,right,expected",
    [
        ("1.10", "1.9", 1),
        ("1.2", "1.2.0", 0),
        ("1.2.3.4", "1.2.3", 1),
        ("1.0-RC1", "1.0", -1),
        ("1.0beta2", "1.0rc1", -1),
        ("1.0dev", "1.0alpha1", -1),
        ("1.0pl1", "1.0", 1),
        ("trunk", "1.0", None),
        ("", "1", None),
    ],
)
def test_version_semantics(left, right, expected):
    assert compare_versions(left, right) == expected


@pytest.mark.parametrize(
    "version,expected",
    [
        ("0.9", "not_affected"),
        ("1.0", "affected"),
        ("1.2.3", "affected"),
        ("1.2.4", "not_affected"),
        ("2.0", "affected"),
        ("2.0.1", "not_affected"),
        ("dev", "unknown"),
    ],
)
def test_multiple_version_ranges_and_corrected_branches(version, expected):
    match = match_advisory(
        {"type": "plugin", "slug": "fixture", "version": version, "identity_confirmed": True},
        parse_record(raw()),
    )
    assert match["classification"] == expected
    assert match["corrected_versions"] == ["1.2.4", "2.0.1"]


def test_identity_uncertainty_and_missing_range_remain_potential_or_unknown():
    c = {"type": "plugin", "slug": "fixture", "version": "1.2"}
    assert match_advisory(c, parse_record(raw()))["classification"] == "potential"
    d = raw()
    d["software"][0]["affected_versions"] = {}
    assert match_advisory(c, parse_record(d))["classification"] == "unknown"


def test_missing_cvss_is_not_fabricated_and_licenses_are_preserved():
    d = raw(cvss=None, cve=None, updated=None)
    record = parse_record(d)
    assert record.score is None and record.cve is None and record.updated is None
    assert record.copyrights == d["copyrights"]
    assert internal_priority(record, {"criticality": "standard"}) == "unknown"


@pytest.mark.parametrize(
    "score,priority",
    [
        (0, "informational"),
        (0.1, "low"),
        (3.9, "low"),
        (4, "medium"),
        (6.9, "medium"),
        (7, "high"),
        (8.9, "high"),
        (9, "critical"),
        (10, "critical"),
    ],
)
def test_priority_boundaries(score, priority):
    record = parse_record(raw(cvss={"score": score, "rating": None}))
    assert internal_priority(record, {"criticality": "standard"}) == priority
    assert record.published_severity is None


def test_site_criticality_changes_internal_priority_not_published_severity():
    r = parse_record(raw(cvss={"score": 4.5, "rating": "Medium"}))
    assert internal_priority(r, {"criticality": "critical"}) == "high"
    assert r.published_severity == "medium" and r.score == 4.5


def provider(handler, **kwargs):
    return WordfenceClient(
        "fixture-api-key",
        terms_accepted=True,
        transport=httpx.MockTransport(handler),
        sleep=lambda _: None,
        **kwargs,
    )


@pytest.mark.integration
def test_authenticated_v3_feed_to_normalized_records():
    calls = []

    def handler(r):
        calls.append(r)
        return httpx.Response(200, json={"fixture-001": raw()})

    feed = provider(handler).fetch()
    assert calls[0].headers["Authorization"] == "Bearer fixture-api-key"
    assert (
        str(calls[0].url)
        == "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
    )
    assert len(feed.records) == 1 and feed.records[0].id == "fixture-001"
    assert not feed.is_stale(datetime.now(UTC))
    assert feed.is_stale(datetime.now(UTC) + timedelta(days=2))


@pytest.mark.parametrize(
    "status,kind",
    [
        (401, "authentication"),
        (403, "authentication"),
        (404, "http"),
        (429, "rate_limit"),
        (500, "http"),
        (503, "http"),
    ],
)
def test_provider_http_errors_never_become_empty_clean_feed(status, kind):
    calls = []

    def handler(r):
        calls.append(r)
        return httpx.Response(status, headers={"Retry-After": "99999"})

    with pytest.raises(FeedError) as e:
        provider(handler).fetch()
    assert e.value.kind == kind
    assert len(calls) == (3 if status in {429, 500, 503} else 1)
    assert "fixture-api-key" not in repr(e.value)


@pytest.mark.parametrize(
    "body",
    [
        b"not JSON",
        b"<html>denied</html>",
        b"{}",
        b'{"id": {"title":"missing fields"}}',
        b'{"fixture-001":',
    ],
)
def test_invalid_empty_or_partial_feed_is_not_usable(body):
    with pytest.raises(FeedError):
        provider(lambda _: httpx.Response(200, content=body)).fetch()


def test_bounded_feed_and_network_errors():
    with pytest.raises(FeedError) as e:
        provider(lambda _: httpx.Response(200, content=b"x" * 3000), max_bytes=1024).fetch()
    assert e.value.kind == "size"

    def failure(r):
        raise httpx.ConnectError("secret fixture-api-key", request=r)

    with pytest.raises(FeedError) as e:
        provider(failure).fetch()
    assert e.value.kind == "network" and "fixture-api-key" not in str(e.value)


def test_terms_and_missing_key_block_network():
    for key, accepted in [("", True), ("fixture-api-key", False)]:
        with pytest.raises(FeedError):
            WordfenceClient(
                key,
                terms_accepted=accepted,
                transport=httpx.MockTransport(lambda _: pytest.fail("must not call")),
            ).fetch()


@pytest.mark.parametrize("failure_type", ["connect", "timeout"])
def test_httpcore_transport_errors_are_wrapped_without_secret_echo(failure_type):
    import httpcore

    def handler(_):
        error = httpcore.ConnectError if failure_type == "connect" else httpcore.ReadTimeout
        raise error("fixture-api-key must never appear")

    with pytest.raises(FeedError) as e:
        provider(handler).fetch()
    assert e.value.kind == "network" and "fixture-api-key" not in str(e.value)


def test_record_count_budget_is_reported_as_size_limit():
    second = raw(id="fixture-002")
    with pytest.raises(FeedError) as e:
        provider(
            lambda _: httpx.Response(200, json={"fixture-001": raw(), "fixture-002": second}),
            max_records=1,
        ).fetch()
    assert e.value.kind == "size"


def test_parse_deadline_bounds_processing_after_download():
    ticks = iter([0, 0, 181])
    with pytest.raises(FeedError) as e:
        provider(
            lambda _: httpx.Response(200, json={"fixture-001": raw()}), clock=lambda: next(ticks)
        ).fetch()
    assert e.value.kind == "timeout"


@pytest.mark.parametrize("failure", ["scope", "protocol"])
def test_pinned_provider_scope_and_partial_protocol_errors_do_not_escape(failure):
    import httpcore

    from sentinel_audit.transport import ScopeError

    def handler(_):
        raise (
            ScopeError("fixture-api-key")
            if failure == "scope"
            else httpcore.RemoteProtocolError("fixture-api-key")
        )

    with pytest.raises(FeedError) as error:
        provider(handler).fetch()
    assert error.value.kind == "network"
    assert "fixture-api-key" not in str(error.value)


@pytest.mark.parametrize("score", [True, "bad", -1, 11, None])
def test_missing_or_invalid_cvss_not_fabricated(score):
    assert parse_record(raw(cvss={"score": score, "rating": "unrecognized"})).score is None


@pytest.mark.parametrize(
    "link",
    [
        None,
        "https://user:pass@example.org/",
        "javascript:alert(1)",
        "https://example.org/\nsecret",
        "https://[malformed/",
    ],
)
def test_reference_validation(link):
    from sentinel_audit.wordfence import safe_reference

    assert safe_reference(link) is False


def test_feed_encoding_download_deadline_and_record_validation():
    with pytest.raises(FeedError):
        provider(
            lambda _: httpx.Response(200, headers={"content-encoding": "br"}, content=b"")
        ).fetch()
    ticks = iter([0, 181])
    with pytest.raises(FeedError) as error:
        provider(
            lambda _: httpx.Response(200, json={"fixture-001": raw()}), clock=lambda: next(ticks)
        ).fetch()
    assert error.value.kind == "timeout"
    with pytest.raises(FeedError):
        parse_record(raw(software=[{"type": "unknown"}]))
    with pytest.raises(FeedError):
        parse_record(raw(title="x" * 128_001))
