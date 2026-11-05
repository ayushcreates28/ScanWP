"""Evidence-based checks. Raw response contents never become finding evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Literal

from .transport import HTTPResult


@dataclass(frozen=True)
class Check:
    key: str
    status: Literal["pass", "fail", "unknown", "info", "skipped"]
    evidence: str
    severity: str = "info"
    category: str = "configuration"
    remediation: str = "Review this observation with the website administrator."


@dataclass(frozen=True)
class Detection:
    confidence: Literal["confirmed", "probable", "insufficient"]
    version: str | None
    signals: tuple[str, ...]


def is_blocked(result: HTTPResult) -> bool:
    body = result.body[:100_000].decode("utf-8", errors="replace")
    challenge = bool(
        re.search(r"(?:cf-chl|cdn-cgi/challenge-platform|captcha-container)", body, re.I)
    )
    return (
        result.status is None
        or not 200 <= result.status < 300
        or result.error not in {None, "size"}
        or challenge
    )


def detect_wordpress(home: HTTPResult, rest: HTTPResult | None = None) -> Detection:
    if is_blocked(home):
        return Detection("insufficient", None, ())
    html = home.body.decode("utf-8", errors="replace")
    signals: list[str] = []
    version = None
    generator = re.search(
        r'<meta\b(?=[^>]*\bname=["\']generator["\'])(?=[^>]*\bcontent=["\']WordPress(?:\s+([0-9][0-9.a-zA-Z-]*))?["\'])[^>]*>',
        html,
        re.I,
    )
    if generator:
        version = generator.group(1)
        signals.append("generator")
    if re.search(r'(?:src|href)=["\'][^"\']*/wp-includes/(?:js|css)/', html, re.I):
        signals.append("core-assets")
    if re.search(
        r'<link\b[^>]*rel=["\']https://api\.w\.org/["\']', html, re.I
    ) or "https://api.w.org" in home.headers.get("link", ""):
        signals.append("rest-link")
    if rest and rest.complete and not is_blocked(rest):
        try:
            data = json.loads(rest.body)
            if (
                isinstance(data, dict)
                and isinstance(data.get("namespaces"), list)
                and "wp/v2" in data["namespaces"]
                and isinstance(data.get("routes"), dict)
                and any(str(k).startswith("/wp/v2/") for k in data["routes"])
            ):
                signals.append("rest-namespace")
        except (ValueError, UnicodeError):
            pass
    confidence: Literal["confirmed", "probable", "insufficient"] = (
        "confirmed"
        if len(signals) >= 2 or "rest-namespace" in signals
        else "probable"
        if signals
        else "insufficient"
    )
    return Detection(confidence, version, tuple(signals))


def assess_headers(result: HTTPResult) -> list[Check]:
    h = result.headers
    csp = h.get("content-security-policy", "")
    frame = re.search(r"(?:^|;)\s*frame-ancestors\s+([^;]+)", csp, re.I)
    protected_frame = bool(
        frame and not set(frame.group(1).split()).intersection({"*", "http:", "https:"})
    )
    rules = [
        ("https", result.url.startswith("https://"), "high", "Use verified HTTPS for transport."),
        (
            "hsts",
            bool(
                re.search(r"max-age\s*=\s*[1-9]\d*", h.get("strict-transport-security", ""), re.I)
            ),
            "medium",
            "Configure a positive HSTS max-age after validating HTTPS.",
        ),
        (
            "nosniff",
            h.get("x-content-type-options", "").lower() == "nosniff",
            "low",
            "Set X-Content-Type-Options: nosniff.",
        ),
        (
            "framing",
            h.get("x-frame-options", "").upper() in {"DENY", "SAMEORIGIN"} or protected_frame,
            "medium",
            "Configure restrictive CSP frame-ancestors or X-Frame-Options.",
        ),
        (
            "csp",
            bool(csp.strip()),
            "low",
            "Develop and test an application-appropriate Content Security Policy.",
        ),
        (
            "referrer",
            h.get("referrer-policy", "").lower()
            in {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"},
            "low",
            "Configure a restrictive Referrer-Policy.",
        ),
    ]
    return [
        Check(
            key,
            "unknown" if is_blocked(result) else "pass" if passed else "fail",
            f"Sampled HTTP status={result.status}; control={key}; observed={passed}. Header values are assessed only for basic presence/value, not full policy effectiveness.",
            severity,
            "headers",
            action,
        )
        for key, passed, severity, action in rules
    ]


def assess_exposure(kind: str, result: HTTPResult) -> Check:
    body = result.body.decode("utf-8", errors="replace")
    signatures = {
        "config": "<?php" in body
        and bool(re.search(r"define\s*\(\s*['\"]DB_PASSWORD", body))
        and "DB_NAME" in body,
        "database": "-- MySQL dump" in body and "CREATE TABLE" in body,
        "env": bool(re.search(r"^DB_PASSWORD\s*=", body, re.M))
        and bool(re.search(r"^(?:DB_NAME|DB_DATABASE|APP_KEY)\s*=", body, re.M)),
        "git": bool(re.fullmatch(r"ref: refs/heads/[A-Za-z0-9_./-]+\s*", body)),
        "debug": bool(
            re.search(r"\[[^\]]+\]\s*PHP (?:Warning|Fatal error|Notice|Parse error)", body)
        ),
        "directory": bool(re.search(r"<title>\s*Index of /[^<]*</title>", body, re.I))
        and "?C=N" in body,
    }
    if result.status in {404, 410} and result.complete:
        return Check(
            "exposure-" + kind, "pass", "The sampled path returned an explicit not-found response."
        )
    if is_blocked(result):
        return Check(
            "exposure-" + kind,
            "unknown",
            "The request was blocked, unavailable or incomplete; disclosure could not be assessed.",
        )
    if signatures.get(kind, False):
        digest = hashlib.sha256(result.body).hexdigest()
        return Check(
            "exposure-" + kind,
            "fail",
            f"A {kind} disclosure signature was observed; response SHA-256={digest}. Contents are deliberately not retained in evidence.",
            "high" if kind in {"config", "database", "env"} else "medium",
            "exposure",
            "Restrict public access to this path and investigate exposure; rotate credentials if actual secret disclosure is confirmed.",
        )
    return Check(
        "exposure-" + kind,
        "unknown",
        "No disclosure signature was observed in the sample; a soft-404 or incomplete response cannot establish absence.",
    )
