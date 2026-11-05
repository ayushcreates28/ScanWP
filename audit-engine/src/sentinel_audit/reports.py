"""Canonical JSON, HTML, XLSX and PDF reporting. No AI-derived totals."""

from __future__ import annotations

import json
import math
import re
import tempfile
from collections import Counter
from datetime import UTC, datetime
from html import escape
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from jinja2 import Environment, StrictUndefined
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.properties import PageSetupProperties
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

from .history import canonicalize, safe_document

ASSESSMENT = "Review recorded findings and incomplete checks. Zero known matches does not establish complete security, absence of malware, or absence of exploitation."


def build_report(
    scans: list[dict[str, Any]],
    *,
    registered_sites: int,
    now: datetime | None = None,
    timezone: str = "Asia/Kolkata",
    test_data: bool = False,
) -> dict[str, Any]:
    safe_document(scans)
    if registered_sites < len(scans) or len({s["site_id"] for s in scans}) != len(scans):
        raise ValueError("One latest scan per registered site is required")
    sites = []
    statuses: Counter[str] = Counter()
    priorities: Counter[str] = Counter()
    changes: Counter[str] = Counter()
    verified = 0
    for raw in scans:
        findings = canonicalize(raw.get("findings", []))
        outstanding = canonicalize(raw.get("outstanding", findings))
        sites.append({**raw, "findings": findings, "outstanding": outstanding})
        statuses[raw["status"]] += 1
        for f in findings:
            if f["status"] == "open":
                priorities[f["priority"]] += 1
                verified += int(f["confidence"] == "confirmed")
        changes.update(c["change"] for c in raw.get("changes", []))
    instant = now or datetime.now(UTC)
    if instant.tzinfo is None:
        raise ValueError("Aware time required")
    return {
        "schema": "scanwp-report/v1",
        "test_data": test_data,
        "generated_at": instant.astimezone(ZoneInfo(timezone)).isoformat(),
        "timezone": timezone,
        "assessment": ASSESSMENT,
        "counts": {
            "registered": registered_sites,
            "complete": statuses["complete"],
            "partial": statuses["partial"],
            "failed": statuses["failed"] + statuses["interrupted"],
            "skipped": statuses["skipped"] + statuses["cancelled"],
            "not_run": registered_sites - len(sites),
            "verified_findings": verified,
            "open_findings": sum(priorities.values()),
            "by_priority": dict(priorities),
            "changes": dict(changes),
        },
        "sites": sites,
    }


TEMPLATE = """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>ScanWP audit report</title><style>body{font:16px/1.6 system-ui,sans-serif;color:#172b46;background:#f3f6fa;margin:0}main{max-width:1120px;margin:auto;padding:40px}h1,h2,h3{line-height:1.3}header{background:#122b46;color:white;padding:28px;border-radius:12px}section,article{background:white;padding:24px;margin:20px 0;border:1px solid #d4dfeb;border-radius:10px}table{border-collapse:collapse;width:100%;font-size:14px}th,td{padding:9px;border-bottom:1px solid #d4dfeb;text-align:left;vertical-align:top;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere}.badge{font-weight:bold;color:#a23421}a{color:#1551a1}small{color:#4b6077}@media print{main{padding:0}article{break-inside:avoid}}</style>
<main><header><h1>WordPress security audit</h1><p>{{ 'TEST DATA ONLY - no live scan' if report.test_data else 'Authorized assessment' }}</p><p>{{ report.generated_at }} | {{ report.timezone }}</p></header>
<section><h2>Portfolio overview</h2><p>{{ report.counts.registered }} registered sites. {{ report.counts.complete }} complete; {{ report.counts.partial }} partial; {{ report.counts.failed }} failed/interrupted; {{ report.counts.skipped }} skipped/cancelled; {{ report.counts.not_run }} not run.</p><p><strong>{{ report.counts.verified_findings }} verified findings</strong>; {{ report.counts.open_findings }} total open observations.</p><p>{{ report.assessment }}</p><pre>{{ report.counts.changes|tojson(indent=2) }}</pre></section>
{% if report.get('summary') %}<section><h2>Management summary</h2><p>{{ report.summary.text }}</p><h3>Priority actions</h3>{% for a in report.summary.actions %}<p>{{ a.site_id }} / {{ a.finding_id }} / {{ a.priority }}: {{ a.remediation }}</p>{% else %}<p>No open actions recorded. Review incomplete checks.</p>{% endfor %}</section>{% endif %}
{% for site in report.sites %}<section><h2>{{ site.site_name|default(site.site_id) }}</h2><p>{{ site.site_url|default('URL unknown') }}</p><p class="badge">Execution: {{ site.status }}</p><p>Scan {{ site.id }}. Started {{ site.started }}. Feed {{ site.feed_status|default('unknown') }}; fetched {{ site.feed_fetched_at|default('unknown',true) }}.</p>
<h3>Installed components</h3><p>Core {{ site.get('inventory',{}).get('core_version','unknown') or 'unknown' }}; PHP {{ site.get('inventory',{}).get('php_version','unknown') or 'unknown' }}</p>
<table><thead><tr><th>Type / component</th><th>Version</th><th>Status</th><th>Update</th><th>Available version</th></tr></thead><tbody>{% for c in site.get('inventory',{}).get('components',[]) %}<tr><td>{{ c.type }} / {{ c.name }}</td><td>{{ c.version or 'unknown' }}</td><td>{{ c.status }}</td><td>{{ c.update_state|default('unknown') }}</td><td>{{ c.latest|default('unknown',true) }}</td></tr>{% endfor %}</tbody></table>
<h3>Findings and observations</h3>{% for f in site.findings if f.status != 'clear' %}<article><h3>{{ f.title }}</h3><p>ID {{ f.id }} | {{ f.priority }} priority | {{ f.status }} | {{ f.confidence }}</p><p>Publisher severity {{ f.published_severity or 'unknown' }}; CVSS {{ f.cvss if f.cvss is not none else 'unknown' }}</p><p>{{ f.evidence }}</p><pre>{{ f.details|tojson(indent=2) }}</pre><p>Action: {{ f.remediation }}</p>{% for ref in f.references %}<p><a rel="noreferrer" href="{{ ref }}">{{ ref }}</a></p>{% endfor %}{% if f.copyrights %}<h4>Source notices</h4><pre>{{ f.copyrights|tojson(indent=2) }}</pre>{% endif %}</article>{% else %}<p>No open findings recorded. Review coverage and failed checks.</p>{% endfor %}
<h3>Check coverage</h3><table><tr><th>Check / path</th><th>Result</th><th>Evidence</th></tr>{% for c in site.get('checks',[]) %}<tr><td>{{ c.key }} {{ c.path|default('') }}</td><td>{{ c.status }}</td><td>{{ c.evidence }}</td></tr>{% endfor %}</table>
<h3>History and outstanding verification</h3><pre>{{ site.get('changes',[])|tojson(indent=2) }}</pre>
<h3>Limitations</h3>{% for limitation in site.get('limitations',[]) %}<p>{{ limitation }}</p>{% endfor %}</section>{% endfor %}</main></html>"""


def excel_value(value: Any) -> Any:
    if value is None:
        return "unknown"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=True)
    if isinstance(value, str):
        value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", value)
        if value.lstrip().startswith(("=", "+", "-", "@")):
            value = "'" + value
        if len(value) > 32700:
            raise ValueError("Excel cell size exceeded; use JSON for full detail")
    return value


def write_excel(report: dict[str, Any], path: Path) -> None:
    book = Workbook()
    summary = book.active
    if summary is None:
        raise RuntimeError("Missing worksheet")
    summary.title = "Summary"
    for summary_row in [
        ("ScanWP audit", "TEST DATA ONLY" if report["test_data"] else report["generated_at"]),
        ("Registered sites", report["counts"]["registered"]),
        ("Complete sites", report["counts"]["complete"]),
        ("Known findings", report["counts"]["verified_findings"]),
        ("Partial sites", report["counts"]["partial"]),
        ("Failed sites", report["counts"]["failed"]),
        ("Assessment", report["assessment"]),
    ]:
        summary.append(summary_row)
    datasets = {
        "Sites": (
            [
                "Site",
                "Name",
                "URL",
                "Status",
                "Started",
                "Feed status",
                "Feed fetched",
                "Limitations",
            ],
            [
                [
                    s["site_id"],
                    s.get("site_name"),
                    s.get("site_url"),
                    s["status"],
                    s["started"],
                    s.get("feed_status"),
                    s.get("feed_fetched_at"),
                    s.get("limitations", []),
                ]
                for s in report["sites"]
            ],
        ),
        "Findings": (
            [
                "Site",
                "Finding ID",
                "Title",
                "Status",
                "Priority",
                "Confidence",
                "Publisher severity",
                "CVSS",
                "Evidence",
                "Action",
                "Details",
                "References",
                "Source notices",
            ],
            [
                [
                    s["site_id"],
                    f["id"],
                    f["title"],
                    f["status"],
                    f["priority"],
                    f["confidence"],
                    f["published_severity"],
                    f["cvss"],
                    f["evidence"],
                    f["remediation"],
                    f["details"],
                    f["references"],
                    f["copyrights"],
                ]
                for s in report["sites"]
                for f in s["findings"]
            ],
        ),
        "Inventory": (
            [
                "Site",
                "Type",
                "Slug",
                "Name",
                "Version",
                "Status",
                "Update",
                "Latest",
                "Auto update",
            ],
            [
                [
                    s["site_id"],
                    c["type"],
                    c["slug"],
                    c["name"],
                    c.get("version"),
                    c["status"],
                    c.get("update_state"),
                    c.get("latest"),
                    c.get("auto_update"),
                ]
                for s in report["sites"]
                for c in s.get("inventory", {}).get("components", [])
            ],
        ),
        "Checks": (
            ["Site", "Check", "Path", "Result", "Evidence"],
            [
                [s["site_id"], c["key"], c.get("path"), c["status"], c["evidence"]]
                for s in report["sites"]
                for c in s.get("checks", [])
            ],
        ),
        "History": (
            ["Site", "Finding ID", "Change"],
            [
                [s["site_id"], c["id"], c["change"]]
                for s in report["sites"]
                for c in s.get("changes", [])
            ],
        ),
    }
    for name, (headers, rows) in datasets.items():
        sheet = book.create_sheet(name)
        sheet.append(headers)
        for row in rows:
            sheet.append([excel_value(v) for v in row])
        sheet.auto_filter.ref = sheet.dimensions
        sheet.freeze_panes = "C2"
    for sheet in book:
        sheet.sheet_view.showGridLines = False
        for cell in sheet[1]:
            cell.fill = PatternFill("solid", fgColor="16344F")
            cell.font = Font(color="FFFFFF", bold=True)
        for row_number, cells_row in enumerate(sheet.iter_rows(min_row=2), start=2):
            wrapped_lines = 1
            for column_index, cell in enumerate(cells_row, start=1):
                cell.alignment = Alignment(vertical="top", wrap_text=True)
                cell.font = Font(name="Aptos", size=11, color="172B46")
                width = 34 if column_index > 2 else 23
                wrapped_lines = max(
                    wrapped_lines,
                    sum(
                        max(1, math.ceil(len(line) / (width - 3)))
                        for line in str(cell.value or "").split("\n")
                    ),
                )
                if sheet.title == "Inventory" and column_index in {5, 8}:
                    cell.number_format = "@"
            sheet.row_dimensions[row_number].height = min(409, max(24, wrapped_lines * 14 + 8))
        for col in range(1, sheet.max_column + 1):
            sheet.column_dimensions[get_column_letter(col)].width = 34 if col > 2 else 23
        sheet.print_title_rows = "1:1"
        sheet.sheet_properties.pageSetUpPr = PageSetupProperties(fitToPage=True)
        sheet.page_setup.orientation = "landscape"
        sheet.page_setup.paperSize = sheet.PAPERSIZE_A3
        sheet.page_setup.fitToWidth = 1
        sheet.page_setup.fitToHeight = 0
    summary.column_dimensions["B"].width = 95
    summary.row_dimensions[7].height = 58
    book.save(path)


def write_pdf(report: dict[str, Any], path: Path) -> None:
    styles = getSampleStyleSheet()
    styles["BodyText"].fontSize = 9
    styles["BodyText"].leading = 13
    styles["BodyText"].wordWrap = "CJK"
    story: list[Any] = []

    def p(text: Any, style: str = "BodyText") -> None:
        # Remote strings are always plain text; no remote images/links are loaded.
        printable = str(text).encode("ascii", "backslashreplace").decode("ascii")
        paragraph = Paragraph(escape(printable).replace("\n", "<br/>"), styles[style])
        if style.startswith("Heading"):
            paragraph.keepWithNext = True
        story.append(paragraph)
        spacer = Spacer(1, 6)
        if style.startswith("Heading"):
            spacer.keepWithNext = True
        story.append(spacer)

    p("WordPress security audit", "Title")
    p(
        "TEST DATA ONLY - no live scan" if report["test_data"] else "Authorized assessment",
        "Heading2",
    )
    p(report["generated_at"])
    p("Known findings: " + str(report["counts"]["verified_findings"]))
    p(report["assessment"])
    for label in ("registered", "complete", "partial", "failed", "skipped", "not_run"):
        p(label.replace("_", " ").capitalize() + ": " + str(report["counts"][label]))
    if report.get("summary"):
        p("Management summary", "Heading2")
        p(report["summary"]["text"])
        p("Priority actions", "Heading2")
        for action in report["summary"]["actions"]:
            p(
                action["site_id"]
                + " / "
                + action["finding_id"]
                + " / "
                + action["priority"]
                + ": "
                + action["remediation"]
            )
    for site in report["sites"]:
        p(site.get("site_name", site["site_id"]), "Heading1")
        p("Execution: " + site["status"])
        p(site.get("site_url", "URL unknown"))
        p("Scan " + site["id"] + " started " + site["started"])
        p(
            "Feed: "
            + str(site.get("feed_status", "unknown"))
            + " / "
            + str(site.get("feed_fetched_at") or "unknown")
        )
        p("Installed components", "Heading2")
        for c in site.get("inventory", {}).get("components", []):
            p(
                f"{c['type']} / {c['name']} / {c.get('version') or 'unknown'} / {c['status']} / update {c.get('update_state', 'unknown')} / latest {c.get('latest') or 'unknown'}"
            )
        p("Findings", "Heading2")
        for f in site["findings"]:
            if f["status"] == "clear":
                continue
            p(f["title"], "Heading3")
            p(f"{f['id']} | {f['status']} | {f['priority']} | {f['confidence']}")
            p(
                "Publisher severity: "
                + str(f["published_severity"] or "unknown")
                + "; CVSS: "
                + str(f["cvss"] if f["cvss"] is not None else "unknown")
            )
            p(f["evidence"])
            p("Action: " + f["remediation"])
            p(json.dumps(f["details"], ensure_ascii=True))
            for reference in f["references"]:
                p(reference)
            if f["copyrights"]:
                p("Source notices: " + json.dumps(f["copyrights"], ensure_ascii=True))
        p("Check coverage", "Heading2")
        for c in site.get("checks", []):
            p(f"{c['key']} {c.get('path', '')} / {c['status']}: {c['evidence']}")
        p("Historical comparison", "Heading2")
        for c in site.get("changes", []):
            p(c["id"] + ": " + c["change"])
        p("Limitations", "Heading2")
        for limitation in site.get("limitations", []):
            p(limitation)

    def footer(canvas: Any, doc: Any) -> None:
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#52677C"))
        canvas.drawString(42, 24, "ScanWP | Confidential audit | Page " + str(doc.page))

    SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=42,
        rightMargin=42,
        topMargin=40,
        bottomMargin=42,
        title="ScanWP audit report",
    ).build(story, onFirstPage=footer, onLaterPages=footer)


def export_report(report: dict[str, Any], output: Path, stem: str = "audit") -> dict[str, Path]:
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,100}", stem):
        raise ValueError("Invalid report filename")
    safe_document(report)
    output.mkdir(parents=True, exist_ok=True)
    paths = {kind: output / (stem + "." + kind) for kind in ("json", "html", "xlsx", "pdf")}
    if output.is_symlink() or any(p.is_symlink() for p in paths.values()):
        raise ValueError("Symlink report paths are not permitted")
    with tempfile.TemporaryDirectory(prefix=".report-", dir=output) as temporary:
        staged = {kind: Path(temporary) / (stem + "." + kind) for kind in paths}
        staged["json"].write_text(
            json.dumps(report, ensure_ascii=True, allow_nan=False, indent=2), encoding="utf-8"
        )
        env = Environment(autoescape=True, undefined=StrictUndefined)
        staged["html"].write_text(env.from_string(TEMPLATE).render(report=report), encoding="utf-8")
        write_excel(report, staged["xlsx"])
        write_pdf(report, staged["pdf"])
        for kind, path in staged.items():
            path.chmod(0o600)
            path.replace(paths[kind])
    return paths
