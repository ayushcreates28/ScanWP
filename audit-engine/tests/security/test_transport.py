import httpx
import pytest

from sentinel_audit.config import SiteConfig
from sentinel_audit.transport import GuardedClient, PinningBackend, ScopeError


def config(**changes):
    return SiteConfig.model_validate(
        {
            "id": "fixture",
            "name": "Fixture",
            "production_url": "https://audit.example.org/",
            "authorized": True,
            "methods": ["public"],
            "rate_limit_per_second": 2,
            **changes,
        }
    )


class Backend:
    def __init__(self):
        self.calls = []

    def connect_tcp(self, host, port, **kwargs):
        self.calls.append((host, port))
        return "stream"


@pytest.mark.security
@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "192.168.0.1",
        "172.16.0.1",
        "224.0.0.1",
        "0.0.0.0",  # noqa: S104 - denied-target fixture, not a listening interface
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "2001:db8::1",
    ],
)
def test_private_dns_answers_never_connect(ip):
    raw = Backend()
    backend = PinningBackend(frozenset({"audit.example.org"}), lambda _: [ip], raw)
    with pytest.raises(ScopeError):
        backend.connect_tcp("audit.example.org", 443)
    assert raw.calls == []


@pytest.mark.security
def test_dns_pin_and_rebinding():
    answers = iter([["1.1.1.1"], ["127.0.0.1"]])
    raw = Backend()
    backend = PinningBackend(frozenset({"audit.example.org"}), lambda _: next(answers), raw)
    assert backend.connect_tcp("audit.example.org", 443) == "stream"
    assert raw.calls == [("1.1.1.1", 443)]
    with pytest.raises(ScopeError):
        backend.connect_tcp("audit.example.org", 443)
    with pytest.raises(ScopeError):
        backend.connect_tcp("other.example.org", 443)


def test_mixed_public_private_dns_is_rejected():
    with pytest.raises(ScopeError):
        PinningBackend(
            frozenset({"audit.example.org"}), lambda _: ["1.1.1.1", "10.0.0.1"], Backend()
        ).connect_tcp("audit.example.org", 443)


def client(handler, **kwargs):
    return GuardedClient(
        config(**kwargs), transport=httpx.MockTransport(handler), sleep=lambda _: None
    )


def test_redirect_does_not_reach_unauthorized_host():
    calls = []

    def handler(r):
        calls.append(str(r.url))
        return httpx.Response(302, headers={"location": "https://evil.example.org/"})

    with client(handler) as c:
        result = c.get("https://audit.example.org/")
    assert not result.complete and result.error == "scope"
    assert len(calls) == 1


def test_inventory_credentials_are_not_redirected_even_to_authorized_host():
    calls = []

    def handler(r):
        calls.append(r)
        return httpx.Response(302, headers={"location": "/another/"})

    with client(handler) as c:
        result = c.get(
            "https://audit.example.org/", headers={"Authorization": "Bearer fixture-secret"}
        )
    assert result.error == "redirect" and len(calls) == 1


def test_bounded_response_and_safe_error_categories():
    with client(lambda _: httpx.Response(200, content=b"x" * 5000), max_response_bytes=1024) as c:
        r = c.get("https://audit.example.org/")
    assert len(r.body) == 1024 and not r.complete and r.error == "size"
    with client(
        lambda _: httpx.Response(200, content=b"data", headers={"content-encoding": "gzip"})
    ) as c:
        r = c.get("https://audit.example.org/")
    assert r.error == "encoding" and not r.complete


@pytest.mark.parametrize("status", [429, 500, 503])
def test_retries_are_bounded_and_request_budget_is_shared(status):
    calls = []

    def handler(r):
        calls.append(r)
        return httpx.Response(status, headers={"retry-after": "99999"})

    with client(handler, max_requests=3) as c:
        r = c.get("https://audit.example.org/")
        after = c.get("https://audit.example.org/next")
    assert len(calls) == 3 and not r.complete
    assert after.error == "budget"


@pytest.mark.parametrize("status", [401, 403, 404])
def test_non_retryable_responses_are_not_retried(status):
    calls = []

    def handler(r):
        calls.append(r)
        return httpx.Response(status)

    with client(handler) as c:
        r = c.get("https://audit.example.org/file.bak")
    assert r.status == status and len(calls) == 1
    assert str(calls[0].url).endswith("file.bak")


def test_errors_are_redacted_and_cancellation_stops_requests():
    import threading

    def handler(r):
        raise httpx.ConnectError("sensitive: fixture-secret", request=r)

    with client(handler, max_requests=2) as c:
        r = c.get("https://audit.example.org/")
    assert r.error == "network" and "fixture-secret" not in repr(r)
    cancel = threading.Event()
    cancel.set()
    with GuardedClient(
        config(),
        transport=httpx.MockTransport(lambda _: pytest.fail("must not request")),
        cancel=cancel,
    ) as c:
        r = c.get("https://audit.example.org/")
    assert r.error == "cancelled"


@pytest.mark.security
@pytest.mark.parametrize("ip", ["2002:7f00:1::", "64:ff9b::7f00:1", "64:ff9b:1::a00:1"])
def test_transition_addresses_cannot_hide_private_destinations(ip):
    raw = Backend()
    with pytest.raises(ScopeError):
        PinningBackend(frozenset({"audit.example.org"}), lambda _: [ip], raw).connect_tcp(
            "audit.example.org", 443
        )
    assert raw.calls == []


@pytest.mark.parametrize("answers", [[], ["not-an-ip"]])
def test_empty_or_malformed_dns_is_fail_closed(answers):
    backend = PinningBackend(frozenset({"audit.example.org"}), lambda _: answers, Backend())
    with pytest.raises(ScopeError):
        backend.connect_tcp("audit.example.org", 443)
    with pytest.raises(ScopeError):
        backend.connect_unix_socket("/socket")


def test_dns_resolution_deduplicates_os_answers(monkeypatch):
    from sentinel_audit.transport import resolve_addresses

    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *a, **kw: [
            (None, None, None, None, ("1.1.1.1", 0)),
            (None, None, None, None, ("1.1.1.1", 0)),
        ],
    )
    assert resolve_addresses("audit.example.org") == ["1.1.1.1"]


def test_write_requests_rejected_at_transport_boundary():
    from sentinel_audit.transport import PinnedTransport

    with PinnedTransport(frozenset({"audit.example.org"})) as transport:
        with pytest.raises(ScopeError):
            transport.handle_request(httpx.Request("POST", "https://audit.example.org"))


def test_redirect_loop_disabled_and_invalid_url():
    with client(lambda _: httpx.Response(302, headers={"location": "/again"})) as c:
        assert c.get("https://audit.example.org").error == "redirect"
        assert c.requests == 4
        assert c.get("http://127.0.0.1").error == "scope"
    with client(lambda _: pytest.fail("No disabled requests"), enabled=False) as c:
        assert c.get("https://audit.example.org").error == "disabled"


def test_retry_date_header_and_time_budget():
    sleeps = []
    with GuardedClient(
        config(),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(503, headers={"retry-after": "tomorrow"})
        ),
        sleep=sleeps.append,
    ) as c:
        assert c.get("https://audit.example.org").error == "http"
    assert sleeps and max(sleeps) <= 5
    with GuardedClient(
        config(),
        transport=httpx.MockTransport(lambda _: httpx.Response(503)),
        clock=lambda: 0,
        sleep=lambda _: None,
        budget_seconds=0.1,
    ) as c:
        assert c.get("https://audit.example.org").error == "budget"


def test_partial_stream_cancellation_and_time_budget():
    import threading

    stop = threading.Event()

    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            stop.set()
            yield b"private"

    with GuardedClient(
        config(),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=Stream())),
        cancel=stop,
        sleep=lambda _: None,
    ) as c:
        assert c.get("https://audit.example.org").error == "cancelled"


def test_scope_and_decoding_failures_redacted():
    def scope(_):
        raise ScopeError("private")

    with client(scope) as c:
        assert c.get("https://audit.example.org").error == "scope"

    def decode(_):
        raise httpx.DecodingError("private")

    with client(decode) as c:
        assert c.get("https://audit.example.org").error == "encoding"
