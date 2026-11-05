import hashlib
import os

import pytest

from sentinel_audit.environment import assess_settings, assess_users
from sentinel_audit.integrity import IntegrityError, compare_manifest, hash_directory
from sentinel_audit.transport import HTTPResult


def test_manifest_tracks_new_changed_deleted_without_claiming_malware():
    old = {
        "a.php": {"sha256": "a" * 64},
        "deleted.php": {"sha256": "b" * 64},
        "unchanged": {"sha256": "c" * 64},
    }
    current = {
        "a.php": {"sha256": "d" * 64},
        "new.php": {"sha256": "e" * 64},
        "unchanged": {"sha256": "c" * 64},
    }
    result = compare_manifest(current, old, trusted=False, complete=True)
    assert {r["path"]: r["state"] for r in result} == {
        "a.php": "modified",
        "deleted.php": "deleted",
        "new.php": "new",
        "unchanged": "unchanged",
    }
    assert all(r["malware_confirmed"] is False for r in result)
    assert compare_manifest(current, old, trusted=True, complete=False)[1]["state"] == "unverified"


@pytest.mark.parametrize("path", ["../escape", "/absolute", "a/../b", "C:/secret", "a\\b"])
def test_corrupted_or_unsafe_manifest_rejected(path):
    with pytest.raises(IntegrityError):
        compare_manifest({path: {"sha256": "a" * 64}}, {}, complete=True)


def test_bad_hash_rejected():
    with pytest.raises(IntegrityError):
        compare_manifest({"file": {"sha256": "bad"}}, {})


def test_hashing_is_bounded_and_records_only_metadata(tmp_path):
    (tmp_path / "uploads").mkdir()
    (tmp_path / "uploads" / "unexpected.php").write_bytes(b'<?php echo "never execute";')
    (tmp_path / "large.bin").write_bytes(b"x" * 100)
    result = hash_directory(tmp_path, approved=True, max_file_bytes=50, max_files=10)
    assert result["complete"] is False
    item = result["files"]["uploads/unexpected.php"]
    assert item["sha256"] == hashlib.sha256(b'<?php echo "never execute";').hexdigest()
    assert item["unexpected_executable"] is True
    assert "never execute" not in repr(result)
    assert result["errors"] == [{"path": "large.bin", "kind": "size"}]
    limited = hash_directory(tmp_path, approved=True, max_files=1)
    assert limited["complete"] is False


def test_unapproved_directory_never_read(tmp_path):
    with pytest.raises(IntegrityError):
        hash_directory(tmp_path, approved=False)


def test_symlink_not_followed(tmp_path):
    target = tmp_path / "original"
    target.write_bytes(b"private")
    try:
        os.symlink(target, tmp_path / "link")
    except OSError:
        pytest.skip("OS does not permit creating symlinks")
    result = hash_directory(tmp_path, approved=True)
    assert result["complete"] is False
    assert {"path": "link", "kind": "symlink"} in result["errors"]


def test_permission_error_is_inconclusive(tmp_path, monkeypatch):
    f = tmp_path / "file"
    f.write_bytes(b"x")
    monkeypatch.setattr(
        "sentinel_audit.integrity.read_hash", lambda *args: (_ for _ in ()).throw(PermissionError())
    )
    result = hash_directory(tmp_path, approved=True)
    assert result["errors"] == [{"path": "file", "kind": "permission"}]


@pytest.mark.parametrize(
    "settings,key,status",
    [
        ({}, "debug", "unknown"),
        ({"debug": True}, "debug", "fail"),
        ({"debug": False}, "debug", "pass"),
        ({"registrationEnabled": True, "defaultRole": "administrator"}, "registration", "fail"),
        ({"registrationEnabled": True, "defaultRole": "subscriber"}, "registration", "info"),
        ({"registrationEnabled": False}, "registration", "pass"),
        ({"phpSecuritySupported": False}, "php-support", "fail"),
    ],
)
def test_settings_evidence(settings, key, status):
    assert {c.key: c.status for c in assess_settings(settings)}[key] == status


@pytest.mark.parametrize(
    "status,body,complete,expected",
    [
        (200, b'[{"id":1,"slug":"author"}]', True, "info"),
        (200, b"[]", True, "pass"),
        (403, b"blocked", True, "unknown"),
        (200, b"not json", True, "unknown"),
        (200, b'[{"id":1}]', False, "unknown"),
    ],
)
def test_user_enumeration_does_not_store_personal_data(status, body, complete, expected):
    result = assess_users(
        HTTPResult(
            "https://audit.example.org/wp-json/wp/v2/users", status, {}, body, complete, None, 1
        )
    )
    assert result.status == expected
    assert "author" not in result.evidence
