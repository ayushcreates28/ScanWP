"""Restore private SQLite history only from this repository's trusted workflow."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from .transport import PinnedTransport


class StateError(ValueError):
    pass


def restore_history(
    repository: str,
    branch: str,
    token: str,
    target: Path,
    *,
    allow_first_run: bool = False,
    transport: httpx.BaseTransport | None = None,
) -> bool:
    if (
        not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
        or not token
        or any(c.isspace() for c in token)
        or not branch
    ):
        raise StateError("Invalid history configuration")
    if target.exists():
        raise StateError("Refusing to replace existing history")
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
    }
    base = f"https://api.github.com/repos/{repository}/actions"
    try:
        with httpx.Client(
            transport=transport or PinnedTransport(frozenset({"api.github.com"})),
            trust_env=False,
            follow_redirects=False,
            timeout=30,
        ) as api:

            def metadata(url: str) -> Any:
                with api.stream("GET", url, headers=headers) as response:
                    if response.status_code != 200:
                        raise StateError("History metadata unavailable")
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) > 2_000_000:
                            raise StateError("History metadata limit")
                    return json.loads(body)

            runs = metadata(
                base
                + "/workflows/monthly-audit.yml/runs?per_page=100&branch="
                + quote(branch, safe="")
            )["workflow_runs"]
            artifact_id = None
            expected_digest = None
            for run in runs:
                if (
                    run["status"] != "completed"
                    or run["event"] not in {"schedule", "workflow_dispatch"}
                    or run["head_branch"] != branch
                    or run["path"] != ".github/workflows/monthly-audit.yml"
                    or run.get("head_repository", {}).get("full_name", "").lower()
                    != repository.lower()
                ):
                    continue
                run_id = run["id"]
                if not isinstance(run_id, int) or isinstance(run_id, bool):
                    raise StateError("Invalid run identifier")
                artifacts = metadata(base + f"/runs/{run_id}/artifacts")["artifacts"]
                matches = [
                    a
                    for a in artifacts
                    if a["name"] == "scanwp-private-history" and not a["expired"]
                ]
                if matches:
                    artifact_id = matches[0]["id"]
                    expected_digest = matches[0].get("digest")
                    break
            if artifact_id is None:
                if allow_first_run:
                    return False
                raise StateError("No retained history found; explicit bootstrap required")
            if not isinstance(artifact_id, int) or isinstance(artifact_id, bool):
                raise StateError("Invalid artifact identifier")
            if not isinstance(expected_digest, str) or not re.fullmatch(
                r"sha256:[a-f0-9]{64}", expected_digest
            ):
                raise StateError("Missing valid artifact digest")
            response = api.get(base + f"/artifacts/{artifact_id}/zip", headers=headers)
            if response.status_code != 302:
                raise StateError("History download unavailable")
            signed = response.headers.get("location", "")
            url = urlsplit(signed)
            host = url.hostname or ""
            if (
                url.scheme != "https"
                or url.username is not None
                or url.password is not None
                or url.port not in {None, 443}
                or not (
                    host.endswith(".blob.core.windows.net")
                    or host.endswith(".githubusercontent.com")
                )
            ):
                raise StateError("Unapproved artifact destination")
        # Signed storage request intentionally uses a separate client without auth.
        with (
            httpx.Client(
                transport=transport or PinnedTransport(frozenset({host})),
                trust_env=False,
                follow_redirects=False,
                timeout=60,
            ) as storage,
            tempfile.TemporaryFile("w+b") as archive,
        ):
            with storage.stream("GET", signed) as download:
                if download.status_code != 200:
                    raise StateError("History storage unavailable")
                size = 0
                digest = hashlib.sha256()
                for chunk in download.iter_bytes(65536):
                    size += len(chunk)
                    if size > 400_000_000:
                        raise StateError("History archive size limit")
                    archive.write(chunk)
                    digest.update(chunk)
            if "sha256:" + digest.hexdigest() != expected_digest:
                raise StateError("History artifact digest mismatch")
            archive.seek(0)
            with zipfile.ZipFile(archive) as package:
                members = package.infolist()
                if (
                    len(members) != 1
                    or members[0].filename != "history.sqlite"
                    or members[0].file_size > 600_000_000
                ):
                    raise StateError("Unexpected history archive members")
                target.parent.mkdir(parents=True, exist_ok=True)
                fd, temporary = tempfile.mkstemp(
                    prefix="history-", suffix=".tmp", dir=target.parent
                )
                try:
                    with os.fdopen(fd, "wb") as output, package.open(members[0]) as source:
                        size = 0
                        while chunk := source.read(65536):
                            size += len(chunk)
                            if size > 600_000_000:
                                raise StateError("History expansion limit")
                            output.write(chunk)
                    path = Path(temporary)
                    with path.open("rb") as check:
                        if check.read(16) != b"SQLite format 3\x00":
                            raise StateError("Invalid history database")
                    connection = sqlite3.connect("file:" + path.as_posix() + "?mode=ro", uri=True)
                    try:
                        connection.execute("PRAGMA trusted_schema=OFF")
                        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                            raise StateError("Corrupt history database")
                    finally:
                        connection.close()
                    path.chmod(0o600)
                    path.replace(target)
                finally:
                    Path(temporary).unlink(missing_ok=True)
        return True
    except StateError:
        raise
    except Exception:
        raise StateError("History restore failed; remote details omitted") from None


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--branch", required=True)
    args = parser.parse_args()
    try:
        restored = restore_history(
            os.environ.get("GITHUB_REPOSITORY", ""),
            args.branch,
            os.environ.get("GH_TOKEN", ""),
            args.target,
            allow_first_run=os.environ.get("SENTINEL_INITIALIZE_HISTORY") == "yes",
        )
        print(
            "Private history restored."
            if restored
            else "Explicit first-run bootstrap; no history restored."
        )
    except StateError as error:
        print(str(error))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
