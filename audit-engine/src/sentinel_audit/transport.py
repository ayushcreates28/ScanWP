"""Read-only HTTP with DNS pinning, TLS hostname preservation and explicit scope."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any, Self
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpcore
import httpx

from .config import SiteConfig, normalize_url


class ScopeError(ValueError):
    """The request would leave the approved network scope."""


def resolve_addresses(host: str) -> list[str]:
    return list(
        dict.fromkeys(
            str(record[4][0]) for record in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        )
    )


class PinningBackend(httpcore.NetworkBackend):
    def __init__(
        self,
        allowed_hosts: frozenset[str],
        resolver: Callable[[str], list[str]] = resolve_addresses,
        backend: httpcore.NetworkBackend | None = None,
    ) -> None:
        self.allowed_hosts = allowed_hosts
        self.resolver = resolver
        self.backend = backend or httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        if host not in self.allowed_hosts or port not in {80, 443}:
            raise ScopeError("Connection outside approved scope")
        addresses = self.resolver(host)
        if not addresses:
            raise ScopeError("DNS returned no usable addresses")
        for address in addresses:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError as exc:
                raise ScopeError("Malformed DNS address") from exc
            if isinstance(ip, ipaddress.IPv6Address) and (
                ip.sixtofour is not None
                or ip.teredo is not None
                or ip in ipaddress.IPv6Network("64:ff9b::/96")
                or ip in ipaddress.IPv6Network("64:ff9b:1::/48")
            ):
                raise ScopeError("IPv6 transition destinations are not permitted")
            if (
                not ip.is_global
                or ip.is_multicast
                or ip.is_unspecified
                or getattr(ip, "ipv4_mapped", None) is not None
            ):
                raise ScopeError("DNS returned a non-public address")
        # Connect to the validated literal, not a second DNS lookup of the host.
        # httpcore retains the original origin for Host, TLS SNI and verification.
        return self.backend.connect_tcp(
            addresses[0],
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    def connect_unix_socket(self, *args: Any, **kwargs: Any) -> httpcore.NetworkStream:
        raise ScopeError("Unix sockets are not permitted")

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class ResponseStream(httpx.SyncByteStream):
    def __init__(self, stream: Any) -> None:
        self.stream = stream

    def __iter__(self) -> Iterator[bytes]:
        yield from self.stream

    def close(self) -> None:
        self.stream.close()


class PinnedTransport(httpx.BaseTransport):
    def __init__(self, hosts: frozenset[str], backend: PinningBackend | None = None) -> None:
        self.pool = httpcore.ConnectionPool(
            ssl_context=ssl.create_default_context(),
            network_backend=backend or PinningBackend(hosts),
            retries=0,
            max_connections=2,
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.method != "GET":
            raise ScopeError("Only read-only GET requests are permitted")
        req = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        response = self.pool.handle_request(req)
        return httpx.Response(
            response.status,
            headers=response.headers,
            stream=ResponseStream(response.stream),
            extensions=response.extensions,
        )

    def close(self) -> None:
        self.pool.close()


@dataclass(frozen=True)
class HTTPResult:
    url: str
    status: int | None
    headers: dict[str, str]
    body: bytes
    complete: bool
    error: str | None
    attempts: int = 1


class GuardedClient:
    def __init__(
        self,
        site: SiteConfig,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        cancel: threading.Event | None = None,
        budget_seconds: float = 120,
    ) -> None:
        self.site = site
        self.client = httpx.Client(
            transport=transport or PinnedTransport(site.allowed_hosts),
            follow_redirects=False,
            trust_env=False,
            timeout=site.timeout_seconds,
        )
        self.sleep = sleep
        self.clock = clock
        self.cancel = cancel or threading.Event()
        self.started = clock()
        self.deadline = self.started + budget_seconds
        self.last_request: float | None = None
        self.requests = 0
        self.origins = {
            (urlsplit(u).scheme, urlsplit(u).hostname)
            for u in [site.production_url, *([site.staging_url] if site.staging_url else [])]
        }

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: Any) -> None:
        self.client.close()

    def scoped_url(self, url: str) -> str:
        validated = urlsplit(normalize_url(url))
        original = urlsplit(url)
        if (validated.scheme, validated.hostname) not in self.origins:
            raise ScopeError("URL is not in the authorized registry")
        return urlunsplit((validated.scheme, validated.netloc, original.path or "/", "", ""))

    def get(
        self, url: str, headers: dict[str, str] | None = None, max_bytes: int | None = None
    ) -> HTTPResult:
        request_headers = {
            "User-Agent": "SentinelAudit/0.2 (authorized read-only audit)",
            "Accept-Encoding": "identity",
            **(headers or {}),
        }
        authenticated = any(k.lower() in {"authorization", "cookie"} for k in request_headers)
        limit = min(max_bytes or self.site.max_response_bytes, self.site.max_response_bytes)

        def failure(error: str, status: int | None = None) -> HTTPResult:
            return HTTPResult(
                url=url, status=status, headers={}, body=b"", complete=False, error=error
            )

        if not self.site.enabled:
            return failure("disabled")
        try:
            url = self.scoped_url(url)
        except ValueError:
            return failure("scope")
        redirects = 0
        retries = 0
        while True:
            if self.cancel.is_set():
                return failure("cancelled")
            if self.requests >= self.site.max_requests or self.clock() >= self.deadline:
                return failure("budget")
            pause = (
                max(
                    0.0,
                    (self.last_request or 0) + 1 / self.site.rate_limit_per_second - self.clock(),
                )
                if self.last_request is not None
                else 0
            )
            if self.clock() + pause >= self.deadline:
                return failure("budget")
            if pause:
                self.sleep(pause)
            self.requests += 1
            self.last_request = self.clock()
            try:
                with self.client.stream(
                    "GET",
                    url,
                    headers=request_headers,
                    timeout=min(self.site.timeout_seconds, max(0.1, self.deadline - self.clock())),
                ) as response:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        if authenticated or redirects >= 3 or "location" not in response.headers:
                            return failure("redirect", response.status_code)
                        try:
                            url = self.scoped_url(urljoin(url, response.headers["location"]))
                        except ValueError:
                            return failure("scope", response.status_code)
                        redirects += 1
                        continue
                    if response.status_code in {429, 500, 502, 503, 504}:
                        if retries < 2 and self.requests < self.site.max_requests:
                            retries += 1
                            try:
                                retry_after = float(response.headers.get("retry-after", "0"))
                            except ValueError:
                                retry_after = 0
                            delay = min(5.0, max(0.25 * 2 ** (retries - 1), retry_after))
                            if self.clock() + delay >= self.deadline:
                                return failure("budget", response.status_code)
                            self.sleep(delay)
                            continue
                        return failure("http", response.status_code)
                    safe_headers = {
                        k: response.headers[k][:4000]
                        for k in [
                            "content-type",
                            "content-security-policy",
                            "x-frame-options",
                            "strict-transport-security",
                            "x-content-type-options",
                            "referrer-policy",
                            "link",
                        ]
                        if k in response.headers
                    }
                    if response.headers.get("content-encoding", "identity").lower() not in {
                        "",
                        "identity",
                    }:
                        return HTTPResult(
                            url, response.status_code, safe_headers, b"", False, "encoding"
                        )
                    body = bytearray()
                    chunks = (
                        [response.content]
                        if response.is_stream_consumed
                        else response.iter_raw(chunk_size=16384)
                    )
                    for chunk in chunks:
                        if self.cancel.is_set():
                            return failure("cancelled")
                        if self.clock() >= self.deadline:
                            return failure("budget")
                        remaining = limit - len(body)
                        body.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            return HTTPResult(
                                url,
                                response.status_code,
                                safe_headers,
                                bytes(body),
                                False,
                                "size",
                                retries + 1,
                            )
                    return HTTPResult(
                        url,
                        response.status_code,
                        safe_headers,
                        bytes(body),
                        True,
                        None,
                        retries + 1,
                    )
            except ScopeError:
                return failure("scope")
            except httpx.DecodingError:
                return failure("encoding")
            except (
                httpx.TransportError,
                httpcore.NetworkError,
                httpcore.TimeoutException,
                OSError,
            ):
                if retries < 2 and self.requests < self.site.max_requests:
                    retries += 1
                    self.sleep(0.25 * 2 ** (retries - 1))
                    continue
                return failure("network")
