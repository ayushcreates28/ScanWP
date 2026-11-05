"""Source-bound summaries; optional Codex selection cannot create factual claims."""

from __future__ import annotations

import json
from typing import Any

import httpx

from .history import safe_document


class SummaryError(ValueError):
    pass


def actions(report: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for site in report["sites"]:
        for f in site["findings"]:
            if f["status"] == "open":
                result.append(
                    {
                        "key": site["site_id"] + "/" + f["id"],
                        "site_id": site["site_id"],
                        "finding_id": f["id"],
                        "priority": f["priority"],
                        "confidence": f["confidence"],
                        "remediation": f["remediation"],
                        "references": f["references"],
                    }
                )
    rank = {
        name: n
        for n, name in enumerate(("critical", "high", "medium", "low", "unknown", "informational"))
    }
    return sorted(result, key=lambda a: (rank[a["priority"]], a["key"]))


def validate_selection(report: dict[str, Any], selection: Any) -> dict[str, list[str]]:
    if not isinstance(selection, dict) or set(selection) != {"finding_keys"}:
        raise SummaryError("Unsupported summary fields")
    selected = selection["finding_keys"]
    allowed = {a["key"] for a in actions(report)}
    if (
        not isinstance(selected, list)
        or len(selected) > 500
        or any(not isinstance(k, str) or k not in allowed for k in selected)
        or len(selected) != len(set(selected))
    ):
        raise SummaryError("Unsupported summary references")
    return {"finding_keys": selected}


def summarize(report: dict[str, Any], selection: Any = None) -> dict[str, Any]:
    safe_document(report)
    ordered = actions(report)
    if selection is not None:
        keys = validate_selection(report, selection)["finding_keys"]
        lookup = {a["key"]: a for a in ordered}
        ordered = [lookup[k] for k in keys] + [a for a in ordered if a["key"] not in keys]
    counts = report["counts"]
    statuses = {s["site_id"]: s["status"] for s in report["sites"]}
    incomplete = any(s != "complete" for s in statuses.values()) or counts["not_run"] > 0
    stale = any(s.get("feed_status") != "fresh" for s in report["sites"])
    return {
        "counts": counts,
        "site_statuses": statuses,
        "actions": ordered,
        "review_required": incomplete or stale,
        "text": f"{counts['verified_findings']} verified finding{'s' if counts['verified_findings'] != 1 else ''} across {counts['registered']} registered sites. "
        f"{counts['complete']} scans complete; {counts['partial']} partial; {counts['failed']} failed/interrupted. "
        + ("Some checks remain incomplete. " if incomplete else "The requested checks completed. ")
        + (
            "Vulnerability intelligence is stale or unavailable. "
            if stale
            else "Fresh vulnerability intelligence was available. "
        )
        + "Review source-linked actions, historical changes and coverage limitations. Zero known matches cannot establish absence of vulnerabilities, malware or exploitation.",
    }


class CodexSummaryClient:
    """Optional Responses API adapter; operator selects a supported Codex model.

    Sends only enumerated identifiers and priorities, no remote narrative, tokens,
    raw HTML, logs or version text. No tools are supplied or executed.
    """

    def __init__(
        self, api_key: str, *, model: str, transport: httpx.BaseTransport | None = None
    ) -> None:
        self._key = api_key
        self.model = model
        self.transport = transport

    def select(self, report: dict[str, Any]) -> dict[str, list[str]]:
        items = actions(report)
        if (
            not self._key
            or any(c.isspace() for c in self._key)
            or not self.model
            or len(items) > 500
        ):
            raise SummaryError("Summary configuration or input limit")
        # Aliases keep arbitrary provider IDs from becoming prompt instructions.
        aliases = {f"f{n}": a["key"] for n, a in enumerate(items)}
        packet = [
            {"id": alias, "priority": a["priority"], "confidence": a["confidence"]}
            for alias, a in zip(aliases, items, strict=True)
        ]
        schema = {
            "type": "object",
            "properties": {
                "finding_keys": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(aliases) or ["none"]},
                }
            },
            "required": ["finding_keys"],
            "additionalProperties": False,
        }
        body = {
            "model": self.model,
            "store": False,
            "tools": [],
            "tool_choice": "none",
            "max_output_tokens": 4096,
            "instructions": "Return a selection of supplied finding identifiers ordered by remediation priority. Never create identifiers, tool calls or prose. Empty input requires an empty array.",
            "input": json.dumps(packet),
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "audit_selection",
                    "strict": True,
                    "schema": schema,
                }
            },
        }
        try:
            with httpx.Client(
                transport=self.transport, trust_env=False, follow_redirects=False, timeout=30
            ) as client:
                with client.stream(
                    "POST",
                    "https://api.openai.com/v1/responses",
                    headers={"Authorization": "Bearer " + self._key},
                    json=body,
                ) as response:
                    if response.status_code != 200:
                        raise SummaryError("Summary provider unavailable")
                    data = bytearray()
                    for chunk in response.iter_bytes():
                        data.extend(chunk)
                        if len(data) > 100_000:
                            raise SummaryError("Summary output limit")
                    raw = json.loads(data)
            output = raw["output"]
            if len(output) != 1 or output[0].get("type") != "message":
                raise SummaryError("Unsupported summary response")
            content = output[0]["content"]
            if len(content) != 1 or content[0].get("type") != "output_text":
                raise SummaryError("Unsupported summary response")
            selected = json.loads(content[0]["text"])
            if (
                not isinstance(selected, dict)
                or set(selected) != {"finding_keys"}
                or not isinstance(selected["finding_keys"], list)
            ):
                raise SummaryError("Unsupported summary response")
            # Accept literal source keys from test/custom transports only if valid;
            # production schema constrains the response to aliases.
            selected["finding_keys"] = [aliases.get(k, k) for k in selected["finding_keys"]]
            return validate_selection(report, selected)
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            if isinstance(exc, SummaryError):
                raise
            raise SummaryError("Summary provider response failed validation") from None
