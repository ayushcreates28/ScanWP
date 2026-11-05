import hashlib
import io
import sqlite3
import zipfile

import httpx
import pytest

from sentinel_audit.github_state import StateError, restore_history


def archive(tmp_path, member="history.sqlite"):
    db = tmp_path / "source"
    connection = sqlite3.connect(db)
    connection.execute("CREATE TABLE fixture(id TEXT)")
    connection.commit()
    connection.close()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(member, db.read_bytes())
    return buf.getvalue()


def transport(
    payload, calls, *, redirect="https://artifact.example.blob.core.windows.net/signed", runs=True
):
    def handler(request):
        calls.append((str(request.url), request.headers.get("authorization")))
        if request.url.path.endswith("/runs"):
            return httpx.Response(
                200,
                json={
                    "workflow_runs": [
                        {
                            "id": 9,
                            "status": "completed",
                            "event": "schedule",
                            "head_branch": "main",
                            "path": ".github/workflows/monthly-audit.yml",
                            "head_repository": {"full_name": "owner/repo"},
                        }
                    ]
                    if runs
                    else []
                },
            )
        if request.url.path.endswith("/artifacts"):
            return httpx.Response(
                200,
                json={
                    "artifacts": [
                        {
                            "id": 99,
                            "name": "scanwp-private-history",
                            "expired": False,
                            "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
                        }
                    ]
                },
            )
        if request.url.host == "api.github.com":
            return httpx.Response(302, headers={"location": redirect})
        return httpx.Response(200, content=payload)

    return httpx.MockTransport(handler)


def test_restore_only_expected_database_and_strip_credentials_on_signed_host(tmp_path):
    calls = []
    target = tmp_path / "restored.sqlite"
    assert restore_history(
        "owner/repo", "main", "fixture-token", target, transport=transport(archive(tmp_path), calls)
    )
    assert target.read_bytes().startswith(b"SQLite format 3")
    assert calls[-1][1] is None and calls[0][1] == "Bearer fixture-token"


@pytest.mark.parametrize("path", ["../history.sqlite", "evil.sql", "nested/history.sqlite"])
def test_reject_zip_traversal_unexpected_files_and_layout(tmp_path, path):
    with pytest.raises(StateError):
        restore_history(
            "owner/repo",
            "main",
            "fixture-token",
            tmp_path / "restored",
            transport=transport(archive(tmp_path, path), []),
        )
    assert not (tmp_path / "restored").exists()


@pytest.mark.parametrize(
    "url",
    [
        "http://artifact.example.com/file",
        "https://evil.example.net/file",
        "https://user:pass@blob.core.windows.net/file",
    ],
)
def test_reject_unapproved_artifact_redirects(tmp_path, url):
    with pytest.raises(StateError):
        restore_history(
            "owner/repo",
            "main",
            "fixture-token",
            tmp_path / "restore",
            transport=transport(b"", [], redirect=url),
        )


def test_missing_history_requires_explicit_bootstrap(tmp_path):
    with pytest.raises(StateError):
        restore_history(
            "owner/repo",
            "main",
            "fixture-token",
            tmp_path / "db",
            transport=transport(b"", [], runs=False),
        )
    assert (
        restore_history(
            "owner/repo",
            "main",
            "fixture-token",
            tmp_path / "db",
            allow_first_run=True,
            transport=transport(b"", [], runs=False),
        )
        is False
    )


def test_archive_digest_must_match_trusted_github_metadata(tmp_path):
    real = transport(archive(tmp_path), [])

    def altered(request):
        response = real.handle_request(request)
        if request.url.path.endswith("/artifacts"):
            data = response.json()
            data["artifacts"][0]["digest"] = "sha256:" + "0" * 64
            return httpx.Response(200, json=data)
        return response

    with pytest.raises(StateError):
        restore_history(
            "owner/repo",
            "main",
            "fixture-token",
            tmp_path / "db",
            transport=httpx.MockTransport(altered),
        )


@pytest.mark.parametrize(
    "case",
    [
        "wrong-repo",
        "metadata-denied",
        "metadata-large",
        "run-id",
        "artifact-id",
        "no-redirect",
        "storage-denied",
        "invalid-zip",
        "invalid-db",
    ],
)
def test_restore_unusable_sources_fail_without_overwriting_history(tmp_path, case):
    data = archive(tmp_path) if case not in {"invalid-zip", "invalid-db"} else b"not a zip"
    if case == "invalid-db":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as package:
            package.writestr("history.sqlite", b"not sqlite")
        data = buf.getvalue()
    real = transport(data, [])

    def alter(request):
        if request.url.path.endswith("/runs"):
            if case == "metadata-denied":
                return httpx.Response(403, text="fixture-token")
            if case == "metadata-large":
                return httpx.Response(200, content=b"x" * 2_000_001)
            response = real.handle_request(request)
            value = response.json()
            if case == "wrong-repo":
                value["workflow_runs"][0]["head_repository"]["full_name"] = "attacker/repo"
            if case == "run-id":
                value["workflow_runs"][0]["id"] = "unsafe"
            return httpx.Response(200, json=value)
        if request.url.path.endswith("/artifacts") and case == "artifact-id":
            response = real.handle_request(request)
            value = response.json()
            value["artifacts"][0]["id"] = "unsafe"
            return httpx.Response(200, json=value)
        if request.url.path.endswith("/zip") and case == "no-redirect":
            return httpx.Response(404)
        if request.url.host != "api.github.com" and case == "storage-denied":
            return httpx.Response(403)
        return real.handle_request(request)

    with pytest.raises(StateError) as error:
        restore_history(
            "owner/repo",
            "main",
            "fixture-token",
            tmp_path / "restored",
            transport=httpx.MockTransport(alter),
        )
    assert "fixture-token" not in str(error.value)
    assert not (tmp_path / "restored").exists()


@pytest.mark.parametrize(
    "repository,token", [("wrong", "key"), ("owner/repo", ""), ("owner/repo", "bad\nkey")]
)
def test_history_configuration_rejected_before_network(tmp_path, repository, token):
    with pytest.raises(StateError):
        restore_history(repository, "main", token, tmp_path / "db")


def test_existing_history_never_replaced(tmp_path):
    target = tmp_path / "existing"
    target.write_text("keep")
    with pytest.raises(StateError):
        restore_history("owner/repo", "main", "key", target)
    assert target.read_text() == "keep"
