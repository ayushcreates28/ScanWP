"""Actual isolated WordPress profile, enabled only by its CI fixture job."""

import hashlib
import os
import shutil
import ssl
import subprocess
import time
from pathlib import Path

import httpx
import pytest

from sentinel_audit.inventory import parse_inventory

pytestmark = [
    pytest.mark.wordpress,
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("SCANWP_WORDPRESS_TEST") != "1",
        reason="Requires isolated Docker WordPress fixture",
    ),
]
ROOT = Path(__file__).resolve().parents[3]
TOKEN = "T" * 64


def wp(*arguments):
    docker = shutil.which("docker")
    assert docker is not None
    result = subprocess.run(  # noqa: S603 - fixed isolated fixture, no remote command input
        [
            docker,
            "compose",
            "-f",
            str(ROOT / "wordpress-test/compose.yml"),
            "run",
            "--rm",
            "--no-deps",
            "wpcli",
            *arguments,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, "Isolated WP-CLI fixture operation failed"
    return result.stdout.strip()


def test_real_wordpress_auth_inventory_read_only_expiry_rotation_revocation():
    # This profile never accepts arbitrary URLs or client-site credentials.
    base = os.environ["SCANWP_WORDPRESS_URL"]
    assert base == "https://localhost:8443"
    context = ssl.create_default_context(cafile=os.environ["SCANWP_WORDPRESS_CERT"])
    endpoint = base + "/wp-json/sentinel-audit/v1/inventory"
    with httpx.Client(
        verify=context, trust_env=False, follow_redirects=False, timeout=15
    ) as client:
        assert client.get(endpoint).status_code == 403
        assert (
            client.get(endpoint, headers={"Authorization": "Bearer " + "X" * 64}).status_code == 403
        )
        auth = {"Authorization": "Bearer " + TOKEN}
        response = client.get(endpoint, headers=auth)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert TOKEN not in response.text
        inventory = parse_inventory(response.json(), "https://audit.example.org/")
        components = inventory["components"]
        by_slug = {c["slug"]: c for c in components}
        assert by_slug["scanwp-active"]["status"] == "active"
        assert by_slug["scanwp-inactive"]["status"] == "inactive"
        assert by_slug["scanwp-fixture"]["status"] == "must-use"
        assert any(c["type"] == "theme" and c["status"] == "active" for c in components)
        assert inventory["core_version"] and inventory["php_version"]
        assert inventory["settings"]["fileEditorDisabled"] is True
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            assert client.request(
                method, endpoint, headers=auth, json={"operation": "update"}
            ).status_code in {404, 405}
        assert (
            client.get(endpoint, headers=auth).json()["components"] == response.json()["components"]
        )
        wp("option", "update", "scanwp_token_expires", str(int(time.time()) - 30))
        assert client.get(endpoint, headers=auth).status_code == 403
        wp("option", "update", "scanwp_token_expires", str(int(time.time()) + 900))
        rotated = "R" * 64
        wp("option", "update", "scanwp_token_hash", hashlib.sha256(rotated.encode()).hexdigest())
        assert client.get(endpoint, headers=auth).status_code == 403
        rotated_auth = {"Authorization": "Bearer " + rotated}
        assert client.get(endpoint, headers=rotated_auth).status_code == 200
        wp("option", "delete", "scanwp_token_hash")
        assert client.get(endpoint, headers=rotated_auth).status_code == 403
