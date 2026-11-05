import httpcore
import httpx
import pytest

from sentinel_audit.config import SiteConfig
from sentinel_audit.scanner import scan_public
from sentinel_audit.transport import (
    GuardedClient,
    PinnedTransport,
    PinningBackend,
)


class MemoryStream(httpcore.NetworkStream):
    def __init__(self):
        self.payload = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody"
        self.writes = []
        self.sni = None
        self.closed = False

    def read(self, max_bytes, timeout=None):
        data, self.payload = self.payload[:max_bytes], self.payload[max_bytes:]
        return data

    def write(self, data, timeout=None):
        self.writes.append(data)

    def close(self):
        self.closed = True

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        assert ssl_context.check_hostname
        self.sni = server_hostname
        return self

    def get_extra_info(self, info):
        return None


class Backend(httpcore.NetworkBackend):
    def __init__(self):
        self.stream = MemoryStream()
        self.host = None

    def connect_tcp(self, host, port, **kwargs):
        self.host = host
        return self.stream


@pytest.mark.integration
@pytest.mark.security
def test_httpcore_receives_public_ip_but_preserves_original_tls_name_and_host():
    raw = Backend()
    transport = PinnedTransport(
        frozenset({"audit.example.org"}),
        PinningBackend(frozenset({"audit.example.org"}), lambda _: ["1.1.1.1"], raw),
    )
    with httpx.Client(transport=transport) as client:
        r = client.get("https://audit.example.org/")
    assert r.text == "body" and raw.host == "1.1.1.1"
    assert raw.stream.sni == "audit.example.org"
    assert b"Host: audit.example.org" in b"".join(raw.stream.writes)
    assert raw.stream.closed


@pytest.mark.integration
def test_public_scanner_collects_header_results_and_safe_probe_evidence():
    site = SiteConfig.model_validate(
        {
            "id": "fixture",
            "name": "Fixture",
            "production_url": "https://audit.example.org/",
            "authorized": True,
            "methods": ["public"],
            "rate_limit_per_second": 2,
        }
    )

    def handler(request):
        if request.url.path == "/":
            return httpx.Response(
                200,
                text='<meta name="generator" content="WordPress 6.9"><script src="/wp-includes/js/a.js"></script>',
            )
        if request.url.path == "/wp-config.php.bak":
            return httpx.Response(
                200, text="<?php define('DB_NAME','fixture');define('DB_PASSWORD','never-store');"
            )
        return httpx.Response(404)

    with GuardedClient(site, transport=httpx.MockTransport(handler), sleep=lambda _: None) as c:
        result = scan_public(c)
    assert result["detection"]["confidence"] == "confirmed"
    assert result["status"] == "partial"
    assert any(x["key"] == "exposure-config" and x["status"] == "fail" for x in result["checks"])
    assert "never-store" not in repr(result)
    assert result["requests"] <= site.max_requests


@pytest.mark.integration
def test_scan_does_not_run_unapproved_public_method():
    site = SiteConfig.model_validate(
        {
            "id": "fixture",
            "name": "Fixture",
            "production_url": "https://audit.example.org/",
            "authorized": True,
            "methods": ["wpcli"],
        }
    )
    with GuardedClient(
        site, transport=httpx.MockTransport(lambda _: pytest.fail("no network"))
    ) as c:
        result = scan_public(c)
    assert result["status"] == "skipped" and result["requests"] == 0
