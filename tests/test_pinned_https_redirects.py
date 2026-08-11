"""Redirect and response contracts for DNS-pinned HTTPS delivery."""

from __future__ import annotations

import json
import socket

import pytest

from appguardrail_core.pinned_https import (
    HTTPSDestination,
    PinnedHTTPSFailure,
    PinnedHTTPSResponse,
    post_json_pinned_https,
)

PUBLIC_IPV4 = "8.8.8.8"
SECOND_PUBLIC_IPV4 = "1.1.1.1"


def _answer(ip_address: str, port: int = 443):
    """Return one TCP IPv4 resolver result."""
    return (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (ip_address, port),
    )


def _resolver(host: str, port: int, *_args: object):
    """Resolve the two fixture origins to distinct public addresses."""
    addresses = {
        "api.example.com": PUBLIC_IPV4,
        "other.example.com": SECOND_PUBLIC_IPV4,
    }
    return [_answer(addresses[host], port)]


class _Response:
    """Small http.client-compatible response used by redirect tests."""

    def __init__(
        self,
        status: int,
        body: bytes = b"{}",
        *,
        reason: str = "",
        headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.status = status
        self.reason = reason
        self._body = body
        self._headers = headers

    def read(self, limit: int = -1) -> bytes:
        """Return at most the requested number of bytes."""
        return self._body if limit < 0 else self._body[:limit]

    def getheaders(self) -> list[tuple[str, str]]:
        """Return response headers in wire order."""
        return list(self._headers)

    def getheader(self, name: str, default: str | None = None) -> str | None:
        """Return one response header using case-insensitive matching."""
        for header_name, value in self._headers:
            if header_name.lower() == name.lower():
                return value
        return default


class _ScriptedConnection:
    """Capture one request and return one scripted response."""

    def __init__(
        self,
        destination: HTTPSDestination,
        timeout: float,
        response: _Response,
        requests: list[dict[str, object]],
    ) -> None:
        self.destination = destination
        self.timeout = timeout
        self.response = response
        self.requests = requests
        self.closed = False

    def request(
        self,
        method: str,
        target: str,
        body: bytes,
        headers: dict[str, str],
    ) -> None:
        """Record method, target, body, headers, origin, and timeout."""
        self.requests.append(
            {
                "origin": self.destination.origin,
                "method": method,
                "target": target,
                "body": body,
                "headers": dict(headers),
                "timeout": self.timeout,
            }
        )

    def getresponse(self) -> _Response:
        """Return the scripted response."""
        return self.response

    def close(self) -> None:
        """Record deterministic connection cleanup."""
        self.closed = True


def _factory(
    responses: list[_Response],
    requests: list[dict[str, object]],
    connections: list[_ScriptedConnection],
):
    """Build a connection factory that consumes responses in order."""
    response_iter = iter(responses)

    def create(destination: HTTPSDestination, timeout: float) -> _ScriptedConnection:
        connection = _ScriptedConnection(
            destination,
            timeout,
            next(response_iter),
            requests,
        )
        connections.append(connection)
        return connection

    return create


def _header_map(request: dict[str, object]) -> dict[str, str]:
    """Normalize recorded request headers for case-insensitive assertions."""
    headers = request["headers"]
    assert isinstance(headers, dict)
    return {str(name).lower(): str(value) for name, value in headers.items()}


def test_cross_origin_307_removes_sensitive_headers_case_insensitively() -> None:
    """Bearer and proxy authorization metadata never crosses an origin boundary."""
    requests: list[dict[str, object]] = []
    connections: list[_ScriptedConnection] = []
    response = post_json_pinned_https(
        "https://api.example.com/api/v1/scans",
        {"findings": []},
        headers={
            "Content-Type": "application/json",
            "aUtHoRiZaTiOn": "Bearer credential-value",
            "pRoXy-AuThOrIzAtIoN": "Basic proxy-value",
            "X-Request-ID": "request-1",
        },
        resolver=_resolver,
        connection_factory=_factory(
            [
                _Response(
                    307,
                    headers=(("Location", "https://other.example.com/ingest"),),
                ),
                _Response(201, body=b'{"id": 7}'),
            ],
            requests,
            connections,
        ),
    )

    assert response.status == 201
    assert json.loads(response.body) == {"id": 7}
    assert len(requests) == 2
    assert "authorization" in _header_map(requests[0])
    assert "proxy-authorization" in _header_map(requests[0])
    redirected_headers = _header_map(requests[1])
    assert "authorization" not in redirected_headers
    assert "proxy-authorization" not in redirected_headers
    assert redirected_headers["content-type"] == "application/json"
    assert redirected_headers["x-request-id"] == "request-1"
    assert requests[1]["target"] == "/ingest"
    assert all(connection.closed for connection in connections)


def test_same_origin_308_preserves_authorization_and_relative_location() -> None:
    """A method-preserving redirect on the same HTTPS origin retains credentials."""
    requests: list[dict[str, object]] = []
    connections: list[_ScriptedConnection] = []
    response = post_json_pinned_https(
        "https://api.example.com/v1/scans",
        {"findings": []},
        headers={"Authorization": "Bearer credential-value"},
        resolver=_resolver,
        connection_factory=_factory(
            [
                _Response(308, headers=(("location", "/v2/scans?source=v1"),)),
                _Response(202, body=b'{"accepted": true}'),
            ],
            requests,
            connections,
        ),
    )

    assert response.status == 202
    assert _header_map(requests[1])["authorization"] == "Bearer credential-value"
    assert requests[1]["target"] == "/v2/scans?source=v1"


@pytest.mark.parametrize("status", [301, 302, 303, 305, 306])
def test_unsupported_redirect_statuses_fail_closed(status: int) -> None:
    """Credential-bearing POST delivery follows only 307 and 308 semantics."""
    with pytest.raises(PinnedHTTPSFailure, match=f"redirect status {status}"):
        post_json_pinned_https(
            "https://api.example.com/v1/scans",
            {},
            headers={"Authorization": "Bearer credential-value"},
            resolver=_resolver,
            connection_factory=_factory(
                [_Response(status, headers=(("Location", "/elsewhere"),))],
                [],
                [],
            ),
        )


def test_redirect_requires_location_and_respects_maximum_hops() -> None:
    """Missing targets and redirect loops terminate with bounded errors."""
    with pytest.raises(PinnedHTTPSFailure, match="missing Location"):
        post_json_pinned_https(
            "https://api.example.com/v1/scans",
            {},
            headers={},
            resolver=_resolver,
            connection_factory=_factory([_Response(307)], [], []),
        )

    with pytest.raises(PinnedHTTPSFailure, match="too many redirects"):
        post_json_pinned_https(
            "https://api.example.com/v1/scans",
            {},
            headers={},
            max_redirects=1,
            resolver=_resolver,
            connection_factory=_factory(
                [
                    _Response(307, headers=(("Location", "/two"),)),
                    _Response(307, headers=(("Location", "/three"),)),
                ],
                [],
                [],
            ),
        )


def test_response_size_is_bounded_and_connection_closes_on_error() -> None:
    """An oversized response cannot exhaust the scanner or leak the connection."""
    connections: list[_ScriptedConnection] = []
    with pytest.raises(PinnedHTTPSFailure, match="response exceeds"):
        post_json_pinned_https(
            "https://api.example.com/v1/scans",
            {},
            headers={},
            max_response_bytes=4,
            resolver=_resolver,
            connection_factory=_factory(
                [_Response(200, body=b"12345")],
                [],
                connections,
            ),
        )

    assert connections[0].closed


def test_response_header_lookup_is_case_insensitive() -> None:
    """Callers inspect bounded response metadata without depending on casing."""
    response = PinnedHTTPSResponse(
        status=202,
        reason="Accepted",
        headers=(("Content-Type", "application/json"),),
        body=b"{}",
    )

    assert response.get_header("content-type") == "application/json"
    assert response.get_header("missing") is None


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"timeout": 0}, "timeout"),
        ({"timeout": True}, "timeout"),
        ({"max_redirects": -1}, "max_redirects"),
        ({"max_redirects": True}, "max_redirects"),
        ({"max_response_bytes": 0}, "max_response_bytes"),
        ({"max_response_bytes": True}, "max_response_bytes"),
    ],
)
def test_transport_bounds_are_validated_before_resolution(
    kwargs: dict[str, object],
    message: str,
) -> None:
    """Invalid resource bounds fail before DNS or credential-bearing I/O."""
    with pytest.raises(ValueError, match=message):
        post_json_pinned_https(
            "https://api.example.com/v1/scans",
            {},
            headers={},
            resolver=lambda *_args: pytest.fail("resolver must not run"),
            **kwargs,
        )


def test_unserializable_json_is_a_bounded_transport_failure() -> None:
    """Serialization errors do not reach DNS or expose Python tracebacks."""
    with pytest.raises(PinnedHTTPSFailure, match="JSON serialization"):
        post_json_pinned_https(
            "https://api.example.com/v1/scans",
            {"bad": object()},
            headers={},
            resolver=lambda *_args: pytest.fail("resolver must not run"),
        )
