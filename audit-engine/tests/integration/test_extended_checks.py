import httpx

from sentinel_audit.config import SiteConfig
from sentinel_audit.scanner import scan_public
from sentinel_audit.transport import GuardedClient


def test_public_scan_records_version_tls_and_user_metadata_without_personal_data():
    site = SiteConfig(
        id="fixture", name="Fixture", production_url="https://audit.example.org", authorized=True
    )

    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, text='<meta name="generator" content="WordPress 6.9">')
        if request.url.path == "/wp-json/wp/v2/users":
            return httpx.Response(200, json=[{"id": 1, "slug": "private-person"}])
        return httpx.Response(404)

    with GuardedClient(
        site, transport=httpx.MockTransport(handler), sleep=lambda _: None
    ) as client:
        result = scan_public(client)
    checks = {c["key"]: c for c in result["checks"]}
    assert checks["version-disclosure"]["status"] == "info"
    assert checks["tls"]["status"] == "pass"
    assert checks["user-enumeration"]["status"] == "info"
    assert "private-person" not in str(result)
