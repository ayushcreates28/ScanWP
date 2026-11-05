"""Bounded approved public checks; no writes, brute force or exploit requests."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any
from urllib.parse import urljoin, urlsplit

from .checks import Check, assess_exposure, assess_headers, detect_wordpress
from .environment import assess_users
from .transport import GuardedClient

PROBES = (
    ("config", "wp-config.php.bak"),
    ("config", "wp-config.php~"),
    ("database", "backup.sql"),
    ("env", ".env"),
    ("git", ".git/HEAD"),
    ("debug", "wp-content/debug.log"),
    ("directory", "backup/"),
    ("directory", "wp-content/uploads/"),
)


def scan_public(client: GuardedClient) -> dict[str, Any]:
    site = client.site
    if "public" not in site.methods or not site.enabled:
        return {
            "site_id": site.id,
            "method": "public",
            "status": "skipped",
            "checks": [],
            "requests": 0,
            "detection": {"confidence": "insufficient", "version": None, "signals": []},
        }
    home = client.get(site.production_url)
    rest = client.get(urljoin(site.production_url, "wp-json/"))
    detection = detect_wordpress(home, rest)
    checks: list[dict[str, Any]] = [
        {**asdict(c), "path": urlsplit(home.url).path, "source_url": home.url}
        for c in assess_headers(home)
    ]
    for check in [
        Check(
            "tls",
            "pass"
            if home.complete and home.status and home.url.startswith("https://")
            else "unknown",
            "HTTPS response received with certificate verification enabled by the production transport. This does not audit cipher suites or the complete TLS configuration.",
        ),
        Check(
            "version-disclosure",
            "info" if detection.version else "unknown",
            "Public WordPress version metadata="
            + str(detection.version)
            + ". Disclosure alone is not a vulnerability.",
        ),
    ]:
        checks.append({**asdict(check), "path": urlsplit(home.url).path, "source_url": home.url})
    users_url = urljoin(site.production_url, "wp-json/wp/v2/users")
    users = assess_users(client.get(users_url, max_bytes=4096))
    checks.append({**asdict(users), "path": "wp-json/wp/v2/users", "source_url": users_url})
    rest_check = Check(
        "rest-api",
        "info" if rest.status == 200 and rest.complete else "unknown",
        f"REST index returned HTTP {rest.status}. Public REST access alone is not a vulnerability.",
    )
    checks.append(
        {
            **asdict(rest_check),
            "path": "wp-json/",
            "source_url": urljoin(site.production_url, "wp-json/"),
        }
    )
    xml = client.get(urljoin(site.production_url, "xmlrpc.php"), max_bytes=4096)
    checks.append(
        {
            **asdict(
                Check(
                    "xmlrpc",
                    "info" if xml.status in {200, 405} and xml.complete else "unknown",
                    f"XML-RPC GET returned HTTP {xml.status}. Availability alone does not establish a vulnerability; no POST or login attempt was sent.",
                )
            ),
            "path": "xmlrpc.php",
            "source_url": urljoin(site.production_url, "xmlrpc.php"),
        }
    )
    for kind, path in PROBES:
        url = urljoin(site.production_url, path)
        result = client.get(url, headers={"Range": "bytes=0-4095"}, max_bytes=4096)
        c = assess_exposure(kind, result)
        checks.append({**asdict(c), "key": c.key, "path": path, "source_url": url})
    incomplete = (
        home.error is not None
        or detection.confidence == "insufficient"
        or any(c["status"] in {"unknown", "skipped"} for c in checks)
    )
    return {
        "site_id": site.id,
        "method": "public",
        "status": "failed" if home.status is None else "partial" if incomplete else "complete",
        "checks": checks,
        "requests": client.requests,
        "detection": asdict(detection),
        "limitations": [
            "Public version and CMS indicators are observations, not an authenticated installed-component inventory.",
            "Only documented bounded GET probes were requested. Missing/blocked/incomplete data is not a clean audit.",
        ],
    }
