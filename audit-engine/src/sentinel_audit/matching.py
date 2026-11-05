"""Conservative version matching; publisher severity and internal priority stay separate."""

from __future__ import annotations

import re
from typing import Any

from packaging.version import InvalidVersion, Version

from .wordfence import Record


def compare_versions(left: str, right: str) -> int | None:
    if (
        not isinstance(left, str)
        or not isinstance(right, str)
        or len(left) > 100
        or len(right) > 100
    ):
        return None

    def parse(value: str) -> Version:
        value = re.sub(r"(?i)(?:[-._]?(?:pl|patch|p))(\d+)$", r".post\1", value)
        return Version(value)

    try:
        a, b = parse(left), parse(right)
        return (a > b) - (a < b)
    except InvalidVersion:
        return None


def in_range(version: str, bounds: dict[str, Any]) -> bool | None:
    if compare_versions(version, version) is None:
        return None
    lower, upper = bounds.get("from_version"), bounds.get("to_version")
    if (
        not isinstance(lower, str)
        or not isinstance(upper, str)
        or not isinstance(bounds.get("from_inclusive"), bool)
        or not isinstance(bounds.get("to_inclusive"), bool)
    ):
        return None
    if lower != "*" and upper != "*":
        ordering = compare_versions(lower, upper)
        if ordering is None or ordering > 0:
            return None
    for endpoint, inclusive, minimum in [
        (lower, bounds["from_inclusive"], True),
        (upper, bounds["to_inclusive"], False),
    ]:
        if endpoint == "*":
            continue
        cmp = compare_versions(version, endpoint)
        if cmp is None:
            return None
        if (
            minimum
            and (cmp < 0 or cmp == 0 and not inclusive)
            or not minimum
            and (cmp > 0 or cmp == 0 and not inclusive)
        ):
            return False
    return True


def match_advisory(component: dict[str, Any], record: Record) -> dict[str, Any]:
    relevant = [
        s
        for s in record.software
        if s["type"] == component.get("type") and s["slug"] == component.get("slug")
    ]
    corrected = list(dict.fromkeys(v for s in relevant for v in s["patched_versions"]))
    outcomes = [
        in_range(component.get("version") or "", r)
        for s in relevant
        for r in s["affected_versions"].values()
    ]
    classification = "not_affected"
    if relevant and (not outcomes or None in outcomes):
        classification = "unknown"
    if True in outcomes:
        classification = "affected" if component.get("identity_confirmed") is True else "potential"
    return {
        "advisory_id": record.id,
        "component_id": component.get("id") or f"{component.get('type')}:{component.get('slug')}",
        "classification": classification,
        "corrected_versions": corrected,
        "published_severity": record.published_severity,
        "cvss": record.score,
        "references": list(record.references),
        "copyrights": record.copyrights,
    }


def internal_priority(record: Record, context: dict[str, Any]) -> str:
    score = record.score
    if score is None:
        priority = record.published_severity or "unknown"
    else:
        priority = (
            "critical"
            if score >= 9
            else "high"
            if score >= 7
            else "medium"
            if score >= 4
            else "low"
            if score > 0
            else "informational"
        )
    levels = ["informational", "low", "medium", "high", "critical"]
    if context.get("criticality") == "critical" and priority in levels[1:-1]:
        priority = levels[levels.index(priority) + 1]
    return priority
