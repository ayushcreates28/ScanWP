"""Metadata-only local integrity checks. Never execute inspected files."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any


class IntegrityError(ValueError):
    pass


def validate_manifest(manifest: dict[str, Any]) -> None:
    if not isinstance(manifest, dict) or len(manifest) > 100_000:
        raise IntegrityError("Invalid manifest")
    for path, item in manifest.items():
        p = PurePosixPath(path)
        if (
            not path
            or p.is_absolute()
            or "\\" in path
            or ":" in path
            or any(v in {".", "..", ""} for v in path.split("/"))
            or not isinstance(item, dict)
            or not re.fullmatch(r"[a-f0-9]{64}", str(item.get("sha256", "")))
        ):
            raise IntegrityError("Invalid manifest path or hash")


def compare_manifest(
    current: dict[str, Any],
    baseline: dict[str, Any],
    *,
    trusted: bool = False,
    complete: bool = False,
) -> list[dict[str, Any]]:
    validate_manifest(current)
    validate_manifest(baseline)
    result = []
    for path in sorted(current.keys() | baseline.keys()):
        if path not in current:
            state = "deleted" if complete else "unverified"
        elif path not in baseline:
            state = "new"
        elif current[path]["sha256"] != baseline[path]["sha256"]:
            state = "modified"
        else:
            state = "known-clean" if trusted else "unchanged"
        result.append(
            {
                "path": path,
                "state": state,
                "malware_confirmed": False,
                "basis": "trusted-reference" if trusted else "previous-baseline",
            }
        )
    return result


def read_hash(path: Path, limit: int) -> tuple[str, int]:
    # O_NOFOLLOW prevents symlink replacement on supported Unix hosts. Windows
    # rejects symlinks/reparse points before open; use an isolated read-only mount
    # for an adversarial local filesystem (see SECURITY.md).
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise IntegrityError("Not a regular file")
        digest = hashlib.sha256()
        size = 0
        while chunk := stream.read(65536):
            size += len(chunk)
            if size > limit:
                raise IntegrityError("File limit")
            digest.update(chunk)
        after = os.fstat(stream.fileno())
        if (before.st_mtime_ns, before.st_size) != (after.st_mtime_ns, after.st_size):
            raise IntegrityError("File changed during read")
    return digest.hexdigest(), size


def hash_directory(
    root: Path, *, approved: bool = False, max_files: int = 10_000, max_file_bytes: int = 10_000_000
) -> dict[str, Any]:
    if not approved or root.is_symlink() or not root.is_dir():
        raise IntegrityError("An explicitly approved regular directory is required")
    root = root.resolve()
    files: dict[str, Any] = {}
    errors: list[dict[str, str]] = []
    count = 0

    def walk_error(_: OSError) -> None:
        errors.append({"path": ".", "kind": "permission"})

    for folder, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
        for name in sorted(dirs + names):
            path = Path(folder) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink() or path.is_junction():
                errors.append({"path": relative, "kind": "symlink"})
                if name in dirs:
                    dirs.remove(name)
                continue
            if name in dirs:
                continue
            count += 1
            if count > max_files:
                errors.append({"path": ".", "kind": "count"})
                return {"files": files, "errors": errors, "complete": False}
            try:
                if path.stat().st_size > max_file_bytes:
                    errors.append({"path": relative, "kind": "size"})
                    continue
                digest, size = read_hash(path, max_file_bytes)
                files[relative] = {
                    "sha256": digest,
                    "size": size,
                    "mtime_ns": path.stat().st_mtime_ns,
                    "unexpected_executable": "uploads" in path.relative_to(root).parts
                    and path.suffix.lower() in {".php", ".phtml", ".phar", ".cgi"},
                }
            except (OSError, IntegrityError):
                errors.append({"path": relative, "kind": "permission"})
    return {"files": files, "errors": errors, "complete": not errors}
