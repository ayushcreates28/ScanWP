"""Authenticated settings and passive exposure observations, without PII."""

from __future__ import annotations

import json
from typing import Any, Literal

from .checks import Check, is_blocked
from .transport import HTTPResult


def assess_settings(settings: dict[str, Any]) -> list[Check]:
    result = []
    for field, key, desired, severity in [
        ("debug", "debug", False, "medium"),
        ("debugDisplay", "debug-display", False, "medium"),
        ("fileEditorDisabled", "file-editor", True, "low"),
        ("forceSSLAdmin", "admin-https", True, "medium"),
        ("phpSecuritySupported", "php-support", True, "medium"),
    ]:
        observed = settings.get(field)
        status: Literal["unknown", "pass", "fail", "info"] = (
            "unknown"
            if not isinstance(observed, bool)
            else "pass"
            if observed == desired
            else "fail"
        )
        result.append(
            Check(
                key,
                status,
                f"Authenticated setting {field}={observed}; this does not establish complete server patch status.",
                severity,
                "environment",
                "Review this setting and hosting support/backport policy with the administrator.",
            )
        )
    registration = settings.get("registrationEnabled")
    role = settings.get("defaultRole")
    status = (
        "unknown"
        if registration is None
        else "pass"
        if registration is False
        else "fail"
        if role in {"administrator", "editor"}
        else "info"
    )
    result.append(
        Check(
            "registration",
            status,
            "Registration="
            + str(registration)
            + "; privileged default role="
            + str(role in {"administrator", "editor"}),
            "high",
            "configuration",
            "Verify that public registration uses only an intended low-privilege role.",
        )
    )
    return result


def assess_users(response: HTTPResult) -> Check:
    status: Literal["unknown", "pass", "fail", "info"] = "unknown"
    count = None
    if response.complete and not is_blocked(response):
        try:
            data = json.loads(response.body)
            if isinstance(data, list) and all(
                isinstance(x, dict) and isinstance(x.get("id"), int) for x in data
            ):
                count = len(data)
                status = "info" if count else "pass"
        except (ValueError, UnicodeError):
            pass
    return Check(
        "user-enumeration",
        status,
        f"Public user collection sample count={count}. Public profile metadata alone is not a vulnerability; identities are not retained.",
    )
