"""Resolution and socket contracts for DNS-pinned HTTPS delivery."""

from __future__ import annotations

import socket
import ssl
from collections.abc import Callable
from typing import Any

import pytest

from appguardrail_core.pinned_https import (
    DestinationValidationError,
    HTTPSDestination,
    PinnedHTTPSConnection,
    resolve_public_https_destination,
)


PUBLIC_IPV4 = "8.8.8.8"
SECOND_PUBLIC_IPV4 = "1.1.1.1"
PUBLIC_IPV6 = "2606:4700:4700::1111"


def _answer(
    ip_address: str,
    port: int = 443,
) -> tuple[int, int, int, str, tuple[Any, ...]]:
    """Return one TCP resolver result for an IPv4 or IPv6 address."""
    if ":" in ip_address:
        return (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            (ip_address, port, 0, 0),
        )
    return (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (ip_address, port),
    )


def _resolver_for(
    answers_by_host: dict[str, list[tuple[int, int, int, str, tuple[Any, ...]]]],
    calls: list[tuple[object, ...]] | None = None,
) -> Callable[..., list[tuple[int, int, int, str, tuple[Any, ...]]]]:
    """Build a deterministic resolver and optionally record exact arguments."""

    def resolve(
        host: str,
        port: int,
        family: int,
        socket_type: int,
        protocol: int,
    ) -> list[tuple[int, int, int, str, tuple[Any, ...]]]:
        if calls is not None:
            calls.append((host, port, family, socket_type, protocol))
        return answers_by_host[host]

    return resolve


def test_destination_pins_normalized_public_tcp_answers() -> None:
    """Resolution produces one stable origin, target, and deduplicated address set."""
    calls: list[tuple[object, ...]] = []
    destination = resolve_public_https_destination(
        "https://EXAMPLE.com:8443/api/v1/scans?mode=full",
        resolver=_resolver_for(
            {
                "example.com": [
                    _answer(PUBLIC_IPV4, 8443),
                    _answer(PUBLIC_IPV6, 8443),
                    _answer(PUBLIC_IPV4, 8443),
                ]
            },
            calls,
        ),
    )

    assert destination.hostname == "example.com"
    assert destination.port == 8443
    assert destination.request_target == "/api/v1/scans?mode=full"
    assert destination.origin == ("https", "example.com", 8443)
    assert [address.ip_address for address in destination.addresses] == [
        PUBLIC_IPV4,
        PUBLIC_IPV6,
    ]
    assert calls == [
        (
            "example.com",
            8443,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
        )
    ]


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/api",
        "file:///tmp/report",
        "https://user:password@example.com/api",
        "https://example.com/api#fragment",
        "https://[fe80::1%25eth0]/api",
        "https://example.com:0/api",
        "https://example.com:65536/api",
        "https:///missing-host",
    ],
)
def test_destination_rejects_ambiguous_or_non_https_identity(url: str) -> None:
    """Credential-bearing requests require an unambiguous public HTTPS identity."""
    with pytest.raises(DestinationValidationError):
        resolve_public_https_destination(
            url,
            resolver=_resolver_for({"example.com": [_answer(PUBLIC_IPV4)]}),
        )


def test_destination_rejects_failed_empty_and_mixed_resolution() -> None:
    """DNS failure, no answers, or one non-global answer rejects the destination."""

    def unavailable(*_args: object) -> list[object]:
        raise socket.gaierror("not found")

    with pytest.raises(DestinationValidationError, match="resolution failed"):
        resolve_public_https_destination("https://example.com", resolver=unavailable)

    with pytest.raises(DestinationValidationError, match="no TCP addresses"):
        resolve_public_https_destination(
            "https://example.com",
            resolver=_resolver_for({"example.com": []}),
        )

    with pytest.raises(DestinationValidationError, match="non-global"):
        resolve_public_https_destination(
            "https://example.com",
            resolver=_resolver_for(
                {"example.com": [_answer(PUBLIC_IPV4), _answer("127.0.0.1")]}
            ),
        )


@pytest.mark.parametrize(
    "ip_address",
    [
        "10.0.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "224.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "::1",
        "::",
        "ff02::1",
        "::ffff:127.0.0.1",
    ],
)
def test_destination_rejects_non_global_address_classes(ip_address: str) -> None:
    """Private, local, metadata, multicast, reserved, and mapped IPs fail closed."""
    with pytest.raises(DestinationValidationError, match="non-global"):
        resolve_public_https_destination(
            "https://example.com",
            resolver=_resolver_for({"example.com": [_answer(ip_address)]}),
        )


class _RawSocket:
    """Record one direct socket connection used by the pinned TLS connection."""

    def __init__(self, *, failure: OSError | None = None) -> None:
        self.failure = failure
        self.timeout: float | None = None
        self.connected_to: tuple[Any, ...] | None = None
        self.closed = False

    def settimeout(self, timeout: float | None) -> None:
        """Record the requested timeout."""
        self.timeout = timeout

    def connect(self, socket_address: tuple[Any, ...]) -> None:
        """Connect to the captured address or raise the fixture error."""
        self.connected_to = socket_address
        if self.failure is not None:
            raise self.failure

    def close(self) -> None:
        """Record cleanup of failed raw sockets."""
        self.closed = True


class _TLSContext:
    """Record the original hostname passed to TLS verification and SNI."""

    def __init__(self) -> None:
        self.verify_mode = ssl.CERT_REQUIRED
        self.check_hostname = True
        self.server_hostnames: list[str] = []

    def wrap_socket(self, raw_socket: _RawSocket, *, server_hostname: str):
        """Return the fixture after recording the verified hostname."""
        self.server_hostnames.append(server_hostname)
        return raw_socket


def _destination_with_addresses(*ip_addresses: str) -> HTTPSDestination:
    """Build a destination through the production normalization boundary."""
    return resolve_public_https_destination(
        "https://api.example.com:8443/api/v1/scans",
        resolver=_resolver_for(
            {"api.example.com": [_answer(value, 8443) for value in ip_addresses]}
        ),
    )


def test_connection_uses_pinned_socket_and_original_tls_hostname() -> None:
    """The TCP peer is pinned while SNI and certificate identity use the URL host."""
    destination = _destination_with_addresses(PUBLIC_IPV4)
    created: list[tuple[int, int, int]] = []
    raw_socket = _RawSocket()

    def socket_factory(family: int, socket_type: int, protocol: int) -> _RawSocket:
        created.append((family, socket_type, protocol))
        return raw_socket

    context = _TLSContext()
    connection = PinnedHTTPSConnection(
        destination,
        timeout=7.5,
        context=context,
        socket_factory=socket_factory,
    )
    connection.connect()

    assert created == [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)]
    assert raw_socket.timeout == 7.5
    assert raw_socket.connected_to == (PUBLIC_IPV4, 8443)
    assert context.server_hostnames == ["api.example.com"]
    assert connection.sock is raw_socket


def test_connection_tries_only_prevalidated_addresses() -> None:
    """Fallback advances through the captured address set without re-resolution."""
    destination = _destination_with_addresses(PUBLIC_IPV4, SECOND_PUBLIC_IPV4)
    first = _RawSocket(failure=OSError("unreachable"))
    second = _RawSocket()
    sockets = iter((first, second))
    context = _TLSContext()

    connection = PinnedHTTPSConnection(
        destination,
        timeout=3,
        context=context,
        socket_factory=lambda *_args: next(sockets),
    )
    connection.connect()

    assert first.connected_to == (PUBLIC_IPV4, 8443)
    assert first.closed
    assert second.connected_to == (SECOND_PUBLIC_IPV4, 8443)
    assert context.server_hostnames == ["api.example.com"]


def test_connection_closes_failed_sockets_and_raises_last_error() -> None:
    """Exhausting the captured set raises instead of performing another lookup."""
    destination = _destination_with_addresses(PUBLIC_IPV4, SECOND_PUBLIC_IPV4)
    first = _RawSocket(failure=OSError("first"))
    second = _RawSocket(failure=OSError("second"))
    sockets = iter((first, second))
    connection = PinnedHTTPSConnection(
        destination,
        timeout=3,
        context=_TLSContext(),
        socket_factory=lambda *_args: next(sockets),
    )

    with pytest.raises(OSError, match="second"):
        connection.connect()

    assert first.closed and second.closed
