import pytest

from sentinel_audit.checks import assess_exposure, assess_headers, detect_wordpress
from sentinel_audit.transport import HTTPResult


def response(body=b"", status=200, complete=True, **headers):
    return HTTPResult(
        url="https://audit.example.org/",
        status=status,
        headers=headers,
        body=body,
        complete=complete,
        error=None,
    )


@pytest.mark.parametrize(
    "body",
    [b"<p>Our wp-content directory</p>", b"<p>We discuss WordPress here</p>", b"plain content"],
)
def test_generic_wordpress_mentions_do_not_confirm_cms(body):
    assert detect_wordpress(response(body)).confidence == "insufficient"


def test_multiple_independent_wordpress_signals_and_custom_paths():
    r = response(
        b'<meta name="generator" content="WordPress 6.9.1"><script src="/wp-includes/js/core.js"></script>'
    )
    d = detect_wordpress(r)
    assert d.confidence == "confirmed" and d.version == "6.9.1"
    d = detect_wordpress(
        response(b'<meta name="generator" content="WordPress 6.9.1">'),
        response(b'{"namespaces":["wp/v2"],"routes":{"/wp/v2/posts":{}}}'),
    )
    assert d.confidence == "confirmed"
    assert (
        detect_wordpress(response(b'<meta name="generator" content="WordPress 6.9">')).confidence
        == "probable"
    )


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_blocked_headers_are_inconclusive(status):
    assert all(c.status == "unknown" for c in assess_headers(response(status=status)))


def test_headers_positive_negative_and_weak_framing():
    checks = assess_headers(
        response(
            **{
                "strict-transport-security": "max-age=31536000",
                "x-content-type-options": "nosniff",
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                "referrer-policy": "strict-origin-when-cross-origin",
            }
        )
    )
    assert all(c.status == "pass" for c in checks)
    missing = assess_headers(response())
    assert any(c.status == "fail" for c in missing)
    weak = assess_headers(response(**{"content-security-policy": "frame-ancestors *"}))
    assert next(c for c in weak if c.key == "framing").status == "fail"


def test_waf_challenge_not_treated_as_successful_homepage():
    r = response(
        b'<title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/cf-chl.js"></script>'
    )
    assert detect_wordpress(r).confidence == "insufficient"
    assert all(c.status == "unknown" for c in assess_headers(r))


@pytest.mark.parametrize(
    "name,body",
    [
        ("config", b"<?php define('DB_NAME','fixture');define('DB_PASSWORD','do-not-store');"),
        ("database", b"-- MySQL dump\nCREATE TABLE t (a int);"),
        ("env", b"DB_PASSWORD=do-not-store\nDB_NAME=fixture"),
        ("git", b"ref: refs/heads/main"),
        ("debug", b"[05-Nov-2026 UTC] PHP Fatal error: fixture"),
        ("directory", b'<title>Index of /backup/</title><a href="?C=N">Name</a>'),
    ],
)
def test_sensitive_signatures_use_redacted_evidence(name, body):
    c = assess_exposure(name, response(body))
    assert c.status == "fail"
    assert "do-not-store" not in repr(c) and "fixture" not in c.evidence


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_blocked_probes_are_not_passed(status):
    assert assess_exposure("config", response(status=status)).status == "unknown"


def test_soft_404_html_and_partial_negative_are_not_disclosures():
    assert assess_exposure("config", response(b"<html>Not found</html>")).status == "unknown"
    assert assess_exposure("config", response(status=404)).status == "pass"
    assert assess_exposure("config", response(b"<html>", complete=False)).status == "unknown"


@pytest.mark.parametrize("policy", ["frame-ancestors * https:", "frame-ancestors https: http:"])
def test_permissive_frame_policy_is_not_protection(policy):
    checks = assess_headers(response(**{"content-security-policy": policy}))
    assert next(c for c in checks if c.key == "framing").status == "fail"
