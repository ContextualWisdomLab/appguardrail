"""Edge and failure contracts for DNS-pinned HTTPS delivery."""

from __future__ import annotations

import http.client
import socket
from collections.abc import Iterator, Mapping
from typing import Any

import pytest

from appguardrail_core import pinned_https as transport


PUBLIC_IPV4 = "8.8.8.8"


def _answer(
    ip_address: str,
    port: int = 443,
    *,
    family: int = socket.AF_INET,
    socket_type: int = socket.SOCK_STREAM,
    protocol: int = socket.IPPROTO_TCP,
    scope_id: int = 0,
) -> tuple[int, int, int, str, tuple[Any, ...]]:
    """Return one configurable resolver answer."""
    socket_address: tuple[Any, ...]
    if family == socket.AF_INET6:
        socket_address = (ip_address, port, 0, scope_id)
    else:
        socket_address = (ip_address, port)
    return family, socket_type, protocol, "", socket_address


def _resolver_with(*answers: tuple[int, int, int, str, tuple[Any, ...]]):
    """Return a deterministic resolver containing the supplied answers."""

    def resolve(*_args: object):
        return list(answers)

    return resolve


@pytest.mark.parametrize(
    "url",
    [
        "",
        "https://example.com/\nnext",
        "https://example.com:invalid/path",
        "https://example.com./path#fragment",
    ],
)
def test_destination_rejects_invalid_url_forms(url: str) -> None:
    """Malformed URL identity fails before resolver output can be trusted."""
    with pytest.raises(transport.DestinationValidationError):
        transport.resolve_public_https_destination(
            url,
            resolver=_resolver_with(_answer(PUBLIC_IPV4)),
        )


def test_destination_rejects_non_string_and_invalid_idna() -> None:
    """Non-text and unencodable host identities fail closed."""
    with pytest.raises(transport.DestinationValidationError):
        transport.resolve_public_https_destination(  # type: ignore[arg-type]
            None,
            resolver=_resolver_with(_answer(PUBLIC_IPV4)),
        )
    with pytest.raises(transport.DestinationValidationError, match="IDNA"):
        transport.resolve_public_https_destination(
            "https://\udcff.example/path",
            resolver=_resolver_with(_answer(PUBLIC_IPV4)),
        )


def test_destination_supports_public_ip_literal_and_default_target() -> None:
    """A public IP literal remains strict HTTPS and uses the root request target."""
    destination = transport.resolve_public_https_destination(
        "https://8.8.8.8",
        resolver=_resolver_with(_answer(PUBLIC_IPV4)),
    )

    assert destination.hostname == PUBLIC_IPV4
    assert destination.port == 443
    assert destination.request_target == "/"
    assert destination.url == "https://8.8.8.8/"


def test_destination_skips_non_tcp_results_but_rejects_an_empty_tcp_set() -> None:
    """Only IPv4/IPv6 TCP stream answers can enter the immutable address set."""
    invalid_answers = [
        (socket.AF_UNIX, socket.SOCK_STREAM, 0, "", ("ignored",)),
        _answer(PUBLIC_IPV4, socket_type=socket.SOCK_DGRAM),
        _answer(PUBLIC_IPV4, protocol=socket.IPPROTO_UDP),
        (socket.AF_INET,),
    ]
    with pytest.raises(transport.DestinationValidationError, match="no TCP addresses"):
        transport.resolve_public_https_destination(
            "https://example.com",
            resolver=lambda *_args: invalid_answers,
        )


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (_answer(PUBLIC_IPV4, port=444), "unexpected port"),
        (_answer("not-an-ip"), "invalid IP"),
        (
            _answer(
                "2606:4700:4700::1111",
                family=socket.AF_INET6,
                scope_id=2,
            ),
            "zone-scoped",
        ),
    ],
)
def test_destination_rejects_hostile_resolver_metadata(
    answer: tuple[int, int, int, str, tuple[Any, ...]],
    message: str,
) -> None:
    """Resolver-controlled port, address, and scope metadata cannot widen trust."""
    with pytest.raises(transport.DestinationValidationError, match=message):
        transport.resolve_public_https_destination(
            "https://example.com",
            resolver=_resolver_with(answer),
        )


class _Socket:
    """Record bind, connect, timeout, and close behavior."""

    def __init__(self, *, wrap_failure: OSError | None = None) -> None:
        self.wrap_failure = wrap_failure
        self.bound_to: tuple[str, int] | None = None
        self.connected_to: tuple[Any, ...] | None = None
        self.timeout: float | None = None
        self.closed = False

    def settimeout(self, timeout: float | None) -> None:
        self.timeout = timeout

    def bind(self, source_address: tuple[str, int]) -> None:
        self.bound_to = source_address

    def connect(self, socket_address: tuple[Any, ...]) -> None:
        self.connected_to = socket_address

    def close(self) -> None:
        self.closed = True


class _Context:
    """Return or reject a fixture TLS socket."""

    def __init__(self, *, failure: OSError | None = None) -> None:
        self.failure = failure

    def wrap_socket(self, raw_socket: _Socket, *, server_hostname: str) -> _Socket:
        assert server_hostname == "example.com"
        if self.failure is not None:
            raise self.failure
        return raw_socket


def _destination() -> transport.HTTPSDestination:
    """Return one production-created destination for connection edge tests."""
    return transport.resolve_public_https_destination(
        "https://example.com/path",
        resolver=_resolver_with(_answer(PUBLIC_IPV4)),
    )


def test_connection_honors_source_address_and_rejects_tunneling() -> None:
    """Pinned sockets preserve an explicit source bind and never enable a proxy tunnel."""
    raw_socket = _Socket()
    connection = transport.PinnedHTTPSConnection(
        _destination(),
        timeout=4,
        context=_Context(),
        socket_factory=lambda *_args: raw_socket,
    )
    connection.source_address = ("0.0.0.0", 0)
    connection.connect()

    assert raw_socket.bound_to == ("0.0.0.0", 0)
    assert raw_socket.connected_to == (PUBLIC_IPV4, 443)

    blocked = transport.PinnedHTTPSConnection(
        _destination(),
        context=_Context(),
        socket_factory=lambda *_args: _Socket(),
    )
    blocked._tunnel_host = "proxy.example"  # noqa: SLF001 - contract edge
    with pytest.raises(OSError, match="tunneling"):
        blocked.connect()


def test_connection_closes_socket_when_tls_wrap_fails() -> None:
    """A failed TLS handshake cannot leak the already connected raw socket."""
    raw_socket = _Socket()
    connection = transport.PinnedHTTPSConnection(
        _destination(),
        context=_Context(failure=OSError("TLS failed")),
        socket_factory=lambda *_args: raw_socket,
    )

    with pytest.raises(OSError, match="TLS failed"):
        connection.connect()

    assert raw_socket.closed


def test_connection_rejects_manually_constructed_empty_address_set() -> None:
    """Public dataclass construction cannot trigger an implicit fallback lookup."""
    destination = transport.HTTPSDestination(
        url="https://example.com/",
        hostname="example.com",
        port=443,
        request_target="/",
        addresses=(),
    )
    connection = transport.PinnedHTTPSConnection(destination)

    with pytest.raises(OSError, match="no validated addresses"):
        connection.connect()


class _DuplicateHeaders(Mapping[str, str]):
    """Mapping fixture exposing case-colliding names through item iteration."""

    def __getitem__(self, key: str) -> str:
        return {"Authorization": "first", "authorization": "second"}[key]

    def __iter__(self) -> Iterator[str]:
        return iter(("Authorization", "authorization"))

    def __len__(self) -> int:
        return 2

    def items(self):
        return (("Authorization", "first"), ("authorization", "second"))


@pytest.mark.parametrize(
    "headers",
    [
        {"Bad Header": "value"},
        {"X-Test": "line\nbreak"},
        {"Host": "attacker.example"},
        {"Content-Length": "1"},
        {"Transfer-Encoding": "chunked"},
        {"Connection": "close"},
        _DuplicateHeaders(),
        {1: "value"},  # type: ignore[dict-item]
        {"X-Test": 1},  # type: ignore[dict-item]
    ],
)
def test_header_validation_fails_before_dns(
    headers: Mapping[str, str],
) -> None:
    """Ambiguous, smuggled, duplicate, and non-text headers fail before resolution."""
    with pytest.raises(ValueError):
        transport.post_json_pinned_https(
            "https://example.com",
            {},
            headers=headers,
            resolver=lambda *_args: pytest.fail("resolver must not run"),
        )


class _SimpleResponse:
    """Provide one bounded final or redirect response."""

    def __init__(
        self,
        status: int,
        *,
        body: bytes = b"{}",
        reason: str = "",
        headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.status = status
        self.reason = reason
        self.body = body
        self.headers = headers

    def read(self, size: int) -> bytes:
        return self.body[:size]

    def getheaders(self):
        return list(self.headers)

    def getheader(self, name: str, default: str | None = None):
        for header_name, value in self.headers:
            if header_name.lower() == name.lower():
                return value
        return default


class _Connection:
    """Capture request defaults or raise one configured error."""

    def __init__(
        self,
        response: _SimpleResponse,
        observed: dict[str, object],
        *,
        failure: BaseException | None = None,
    ) -> None:
        self.response = response
        self.observed = observed
        self.failure = failure
        self.closed = False

    def request(self, method: str, target: str, body: bytes, headers: dict[str, str]):
        if self.failure is not None:
            raise self.failure
        self.observed.update(method=method, target=target, body=body, headers=headers)

    def getresponse(self):
        return self.response

    def close(self) -> None:
        self.closed = True


def test_transport_adds_json_defaults_and_accepts_exact_response_boundary() -> None:
    """A final response at the byte limit is returned with deterministic request defaults."""
    observed: dict[str, object] = {}
    connection = _Connection(_SimpleResponse(204, body=b"1234"), observed)

    result = transport.post_json_pinned_https(
        "https://example.com/path",
        {"value": 1},
        max_response_bytes=4,
        resolver=_resolver_with(_answer(PUBLIC_IPV4)),
        connection_factory=lambda *_args: connection,
    )

    assert result.status == 204
    assert result.body == b"1234"
    headers = observed["headers"]
    assert isinstance(headers, dict)
    assert headers["Content-Type"] == "application/json"
    assert headers["Accept"] == "application/json"
    assert connection.closed


@pytest.mark.parametrize("failure", [OSError("socket"), http.client.HTTPException("protocol-private-detail")])
def test_transport_wraps_connection_failures_without_details(failure: BaseException) -> None:
    """Socket and protocol errors become one bounded transport category."""
    connection = _Connection(_SimpleResponse(200), {}, failure=failure)

    with pytest.raises(transport.PinnedHTTPSFailure, match="delivery failed") as error:
        transport.post_json_pinned_https(
            "https://example.com",
            {},
            resolver=_resolver_with(_answer(PUBLIC_IPV4)),
            connection_factory=lambda *_args: connection,
        )

    assert str(failure) not in str(error.value)
    assert connection.closed


def test_redirect_rejects_control_characters_and_non_https_targets() -> None:
    """Redirect metadata cannot inject a request line or downgrade transport security."""
    for location in ("/next\nInjected: value", "http://example.com/next"):
        connection = _Connection(
            _SimpleResponse(307, headers=(("Location", location),)),
            {},
        )
        with pytest.raises(transport.PinnedHTTPSFailure):
            transport.post_json_pinned_https(
                "https://example.com/start",
                {},
                resolver=_resolver_with(_answer(PUBLIC_IPV4)),
                connection_factory=lambda *_args, connection=connection: connection,
            )
        assert connection.closed


def test_zero_redirect_budget_rejects_the_first_redirect() -> None:
    """A zero-hop policy does not permit a single method-preserving redirect."""
    connection = _Connection(
        _SimpleResponse(308, headers=(("Location", "/next"),)),
        {},
    )
    with pytest.raises(transport.PinnedHTTPSFailure, match="too many redirects"):
        transport.post_json_pinned_https(
            "https://example.com/start",
            {},
            max_redirects=0,
            resolver=_resolver_with(_answer(PUBLIC_IPV4)),
            connection_factory=lambda *_args: connection,
        )
