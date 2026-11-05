import json

import pytest

from sentinel_audit.cli import main


def test_secret_bundle_injected_without_logging(tmp_path, monkeypatch):
    from sentinel_audit.cli import secret_environment

    path = registry(tmp_path, methods=["inventory"], connector_token_env="SENTINEL_FIXTURE_TOKEN")
    from sentinel_audit.config import load_config

    monkeypatch.setenv(
        "SENTINEL_CONNECTOR_TOKENS_JSON", json.dumps({"SENTINEL_FIXTURE_TOKEN": "a" * 64})
    )
    assert secret_environment(load_config(path))["SENTINEL_FIXTURE_TOKEN"] == "a" * 64
    monkeypatch.setenv("SENTINEL_CONNECTOR_TOKENS_JSON", json.dumps({"PATH": "unexpected"}))
    with pytest.raises(ValueError):
        secret_environment(load_config(path))


def registry(tmp_path, **changes):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "sites": [
                    {
                        "id": "fixture",
                        "name": "Fixture",
                        "production_url": "https://audit.example.org",
                        "authorized": True,
                        **changes,
                    }
                ]
            }
        )
    )
    return path


def test_validate_never_uses_network(tmp_path, capsys):
    path = registry(tmp_path)
    assert main(["validate", "--config", str(path)]) == 0
    assert "Registry valid" in capsys.readouterr().out


def test_scanning_requires_explicit_runtime_authorization(tmp_path, capsys):
    path = registry(tmp_path)
    assert (
        main(
            [
                "scan",
                "--config",
                str(path),
                "--db",
                str(tmp_path / "db"),
                "--output",
                str(tmp_path / "out"),
            ]
        )
        == 2
    )
    assert "--live" in capsys.readouterr().out
    assert not (tmp_path / "db").exists()


def test_disabled_registry_no_feed_request_and_no_production_network(tmp_path, capsys, monkeypatch):
    path = registry(tmp_path, enabled=False)
    monkeypatch.setattr(
        "sentinel_audit.cli.WordfenceClient.fetch",
        lambda _: pytest.fail("No feed request should be made"),
    )
    assert (
        main(
            [
                "scan",
                "--live",
                "--config",
                str(path),
                "--db",
                str(tmp_path / "db"),
                "--output",
                str(tmp_path / "out"),
            ]
        )
        == 0
    )
    assert (tmp_path / "out" / "consolidated.json").exists()


def test_demo_generates_test_data_without_live_network(tmp_path):
    assert main(["demo", "--output", str(tmp_path / "reports")]) == 0
    data = json.loads((tmp_path / "reports" / "consolidated.json").read_text())
    assert data["test_data"] is True
    assert data["counts"]["registered"] == 2


def test_invalid_config_error_does_not_echo_secret_values(tmp_path, capsys):
    path = registry(tmp_path, password="do-not-echo")
    assert main(["validate", "--config", str(path)]) == 2
    assert "do-not-echo" not in capsys.readouterr().out


def test_site_selection_and_partial_failure_exit(tmp_path, monkeypatch, capsys):
    path = registry(tmp_path)
    monkeypatch.setattr(
        "sentinel_audit.cli.run_audits", lambda *a, **kw: {"status": "partial", "scans": []}
    )
    args = [
        "scan",
        "--live",
        "--config",
        str(path),
        "--db",
        str(tmp_path / "db"),
        "--output",
        str(tmp_path / "out"),
        "--site",
        "fixture",
    ]
    assert main(args) == 1
    args[-1] = "unknown"
    assert main(args) == 2


def test_scheduled_not_due_and_already_complete_do_not_scan(tmp_path, monkeypatch, capsys):
    from datetime import UTC, datetime

    from sentinel_audit.history import Store

    path = registry(tmp_path)
    db = tmp_path / "db"
    args = [
        "scan",
        "--live",
        "--scheduled",
        "--config",
        str(path),
        "--db",
        str(db),
        "--output",
        str(tmp_path / "out"),
    ]
    monkeypatch.setattr("sentinel_audit.cli.due_period", lambda *a: None)
    assert main(args) == 0
    store = Store(db)
    run = store.begin("fixture", datetime.now(UTC))
    store.finish(run, "complete", {"findings": []})
    monkeypatch.setattr("sentinel_audit.cli.due_period", lambda *a: "2026-11")
    assert main(args) == 0
    assert "already complete" in capsys.readouterr().out


def test_feed_failure_continues_and_codex_failure_retains_summary(tmp_path, monkeypatch):
    from sentinel_audit.reports import build_report
    from sentinel_audit.summary import SummaryError
    from sentinel_audit.wordfence import FeedError

    path = registry(tmp_path, methods=["inventory"], connector_token_env="SENTINEL_FIXTURE_TOKEN")

    def feed_fail(_):
        raise FeedError("network")

    def summary_fail(*_):
        raise SummaryError("Unavailable")

    monkeypatch.setattr("sentinel_audit.cli.WordfenceClient.fetch", feed_fail)
    report = build_report([], registered_sites=1)
    from sentinel_audit.summary import summarize

    report["summary"] = summarize(report)
    monkeypatch.setattr(
        "sentinel_audit.cli.run_audits",
        lambda *a, **kw: {"status": "partial", "scans": [], "report": report},
    )
    monkeypatch.setattr("sentinel_audit.cli.CodexSummaryClient.select", summary_fail)
    assert (
        main(
            [
                "scan",
                "--live",
                "--codex-summary",
                "--config",
                str(path),
                "--db",
                str(tmp_path / "db"),
                "--output",
                str(tmp_path / "out"),
            ]
        )
        == 1
    )
    assert "deterministic" in report["summary"]["ai_review"]


def test_offline_inputs_are_bounded(tmp_path):
    from sentinel_audit.cli import offline_files
    from sentinel_audit.config import load_config

    config = load_config(registry(tmp_path))
    assert offline_files(None, config) == {}
    file = tmp_path / "fixture.json"
    file.write_text('{"fixture":true}')
    assert offline_files(tmp_path, config)["fixture"] == {"fixture": True}
    with file.open("wb") as stream:
        stream.truncate(10_000_001)
    with pytest.raises(ValueError):
        offline_files(tmp_path, config)


def test_single_site_selection_accepts_bundle_for_full_registry(tmp_path, monkeypatch):
    path = registry(tmp_path, methods=["inventory"], connector_token_env="SENTINEL_FIXTURE_TOKEN")
    data = json.loads(path.read_text())
    data["sites"].append(
        {
            **data["sites"][0],
            "id": "other",
            "production_url": "https://other.example.org",
            "connector_token_env": "SENTINEL_OTHER_TOKEN",
        }
    )
    path.write_text(json.dumps(data))
    monkeypatch.setenv(
        "SENTINEL_CONNECTOR_TOKENS_JSON",
        json.dumps({"SENTINEL_FIXTURE_TOKEN": "a" * 64, "SENTINEL_OTHER_TOKEN": "b" * 64}),
    )
    monkeypatch.setattr("sentinel_audit.cli.WordfenceClient.fetch", lambda _: None)
    monkeypatch.setattr(
        "sentinel_audit.cli.run_audits", lambda *a, **kw: {"status": "complete", "scans": []}
    )
    assert (
        main(
            [
                "scan",
                "--live",
                "--site",
                "fixture",
                "--config",
                str(path),
                "--db",
                str(tmp_path / "db"),
                "--output",
                str(tmp_path / "out"),
            ]
        )
        == 0
    )
