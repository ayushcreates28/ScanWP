import json
from datetime import UTC, datetime

import pytest
from openpyxl import load_workbook
from pypdf import PdfReader

from sentinel_audit.reports import build_report, export_report


def scan(site="fixture", count=1, status="partial"):
    return {
        "id": "fixture-run",
        "site_id": site,
        "site_name": "TEST DATA " + site,
        "site_url": "https://audit.example.org/",
        "started": "2026-11-01T03:47:00+00:00",
        "status": status,
        "feed_fetched_at": None,
        "feed_status": "unavailable",
        "methods": ["inventory"],
        "inventory": {
            "core_version": "6.9",
            "php_version": None,
            "components": [
                {
                    "id": "p:fixture",
                    "type": "plugin",
                    "name": '=HYPERLINK("bad")',
                    "slug": "fixture",
                    "version": "1.0",
                    "status": "active",
                    "update_state": "available",
                    "latest": "2.0",
                }
            ],
        },
        "checks": [{"key": "fixture", "status": "unknown", "evidence": "Blocked"}],
        "findings": [
            {
                "id": f"f-{i}",
                "status": "open",
                "title": "<script>alert(1)</script> " + ("Long finding " * 12),
                "priority": "high",
                "category": "vulnerability",
                "evidence": "TEST DATA observation <img src=x>",
                "references": ["https://www.wordfence.com/threat-intel/"],
                "confidence": "confirmed",
                "copyrights": {"fixture": {"notice": "TEST ONLY LICENSE"}},
            }
            for i in range(count)
        ],
        "changes": [{"id": "f-0", "change": "new"}] if count else [],
        "limitations": ["TEST DATA ONLY; no live scan performed."],
    }


def test_report_counts_canonical_deduplication_site_isolation_and_timezone():
    a = scan()
    a["findings"] *= 2
    report = build_report(
        [a, scan("other", 0, "failed")],
        registered_sites=3,
        now=datetime(2026, 11, 1, 3, 47, tzinfo=UTC),
    )
    assert report["counts"]["registered"] == 3
    assert report["counts"]["partial"] == 1 and report["counts"]["failed"] == 1
    assert report["counts"]["not_run"] == 1 and report["counts"]["verified_findings"] == 1
    assert report["generated_at"].startswith("2026-11-01T09:17:00")
    assert len(report["sites"][0]["findings"]) == 1
    assert report["sites"][1]["findings"] == []
    assert "secure" not in report["assessment"].lower()


@pytest.mark.integration
@pytest.mark.parametrize("count", [0, 1, 220])
def test_all_exports_round_trip_counts_safe_text_and_pagination(tmp_path, count):
    report = build_report(
        [scan(count=count)],
        registered_sites=1,
        now=datetime(2026, 11, 1, tzinfo=UTC),
        test_data=True,
    )
    paths = export_report(report, tmp_path, "fixture")
    data = json.loads(paths["json"].read_text())
    assert data["counts"]["verified_findings"] == count and data["test_data"] is True
    html = paths["html"].read_text()
    assert "<script>alert" not in html and "TEST DATA" in html
    assert "&lt;script&gt;" in html if count else True
    book = load_workbook(paths["xlsx"], data_only=False)
    assert book["Summary"]["B4"].value == count
    assert book["Inventory"]["D2"].data_type == "s"
    assert book["Inventory"]["D2"].value.startswith("'=")
    assert book["Findings"].max_row == count + 1
    assert all(cell.data_type != "f" for sheet in book for row in sheet for cell in row)
    text = "\n".join(page.extract_text() for page in PdfReader(paths["pdf"]).pages)
    assert "TEST DATA" in text and "Known findings" in text
    assert "TEST ONLY LICENSE" in text if count else True
    if count == 220:
        assert len(PdfReader(paths["pdf"]).pages) > 10


@pytest.mark.parametrize("stem", ["../secret", "a/b", "x\\y", ""])
def test_export_filename_is_bounded_to_output_directory(tmp_path, stem):
    with pytest.raises(ValueError):
        export_report(build_report([], registered_sites=0), tmp_path, stem)


def test_report_rejects_credentials_and_invalid_sources():
    value = scan()
    value["inventory"]["password"] = "must-not-export"
    with pytest.raises(ValueError):
        build_report([value], registered_sites=1)


def test_pdf_uses_explicit_unknown_and_includes_management_summary(tmp_path):
    from sentinel_audit.summary import summarize

    report = build_report([scan()], registered_sites=1, test_data=True)
    report["summary"] = summarize(report)
    paths = export_report(report, tmp_path, "unknown")
    text = "\n".join(p.extract_text() for p in PdfReader(paths["pdf"]).pages)
    assert "CVSS: unknown" in text
    assert "Management summary" in text
    assert report["summary"]["text"] in paths["html"].read_text()


def test_format_failure_does_not_leave_published_partial_report(tmp_path, monkeypatch):
    def fail(*_):
        raise OSError("PDF failure")

    monkeypatch.setattr("sentinel_audit.reports.write_pdf", fail)
    with pytest.raises(OSError):
        export_report(build_report([], registered_sites=0), tmp_path, "atomic")
    assert not list(tmp_path.glob("atomic.*"))
    value = scan()
    value["findings"][0]["references"] = ["javascript:alert(1)"]
    with pytest.raises(ValueError):
        build_report([value], registered_sites=1)
