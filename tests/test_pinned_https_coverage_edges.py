"""Exact statement-coverage edges for DNS-pinned HTTPS delivery."""

from __future__ import annotations

import socket
import urllib.parse

import pytest

from appguardrail_core import pinned_https as transport

PUBLIC_IPV4 = "8.8.8.8"


def _answer(
    ip_address: str,
    port: int = 443,
    *,
    family: int = socket.AF_INET,
    socket_address: tuple[object, ...] | None = None,
):
    """Return one TCP resolver answer with optionally hostile socket metadata."""
    return (
        family,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (
            socket_address
            if socket_address is not None
            else (
                (ip_address, port, 0, 0)
                if family == socket.AF_INET6
                else (ip_address, port)
            )
        ),
    )


def _resolver_with(*answers: tuple[object, ...]):
    """Return a deterministic resolver containing the supplied answers."""

    def resolve(*_args: object):
        return list(answers)

    return resolve


def test_hostname_rejects_overlong_identity_after_idna_normalization() -> None:
    """A syntactically encodable hostname cannot exceed the DNS identity bound."""
    hostname = "a." * 127 + "a"
    assert len(hostname) == 255

    with pytest.raises(
        transport.DestinationValidationError, match="hostname is invalid"
    ):
        transport.resolve_public_https_destination(
            f"https://{hostname}/path",
            resolver=lambda *_args: pytest.fail("resolver must not run"),
        )


@pytest.mark.parametrize("url", ["https://127.0.0.1/", "https://[::1]/"])
def test_non_global_ip_literal_is_rejected_before_resolution(url: str) -> None:
    """A private or loopback literal cannot rely on a later resolver decision."""
    with pytest.raises(transport.DestinationValidationError, match="non-global"):
        transport.resolve_public_https_destination(
            url,
            resolver=lambda *_args: pytest.fail("resolver must not run"),
        )


def test_request_target_normalizer_handles_relative_defensive_input() -> None:
    """The defensive target helper always returns HTTP origin-form syntax."""
    parts = urllib.parse.SplitResult(
        scheme="https",
        netloc="example.com",
        path="relative path",
        query="value=one two",
        fragment="",
    )

    assert transport._quoted_request_target(parts) == "/relative%20path?value=one%20two"


def test_resolver_answer_with_short_socket_tuple_is_ignored() -> None:
    """An incomplete sockaddr never becomes a connectable validated address."""
    with pytest.raises(transport.DestinationValidationError, match="no TCP addresses"):
        transport.resolve_public_https_destination(
            "https://example.com",
            resolver=_resolver_with(
                _answer(PUBLIC_IPV4, socket_address=(PUBLIC_IPV4,))
            ),
        )


def test_resolver_answer_with_textual_zone_is_rejected() -> None:
    """A percent-encoded or textual interface scope cannot bypass zone rejection."""
    with pytest.raises(transport.DestinationValidationError, match="zone-scoped"):
        transport.resolve_public_https_destination(
            "https://example.com",
            resolver=_resolver_with(
                _answer(
                    "2606:4700:4700::1111%eth0",
                    family=socket.AF_INET6,
                    socket_address=("2606:4700:4700::1111%eth0", 443, 0, 0),
                )
            ),
        )


def test_url_parser_failure_is_bounded() -> None:
    """Malformed bracketed authority syntax is translated to a validation error."""
    with pytest.raises(transport.DestinationValidationError, match="URL is invalid"):
        transport.resolve_public_https_destination(
            "https://[broken/path",
            resolver=lambda *_args: pytest.fail("resolver must not run"),
        )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout": "fast"},
        {"max_redirects": 1.5},
        {"max_response_bytes": 1.5},
    ],
)
def test_non_numeric_or_non_integer_bounds_fail_before_resolution(
    kwargs: dict[str, object],
) -> None:
    """Type-invalid resource bounds never reach JSON serialization or DNS."""
    with pytest.raises(ValueError):
        transport.post_json_pinned_https(
            "https://example.com",
            {},
            resolver=lambda *_args: pytest.fail("resolver must not run"),
            **kwargs,
        )


def test_default_connection_factory_returns_the_pinned_connection() -> None:
    """The production factory preserves destination identity and timeout."""
    destination = transport.resolve_public_https_destination(
        "https://example.com/path",
        resolver=_resolver_with(_answer(PUBLIC_IPV4)),
    )

    connection = transport._default_connection_factory(destination, 9.5)

    assert isinstance(connection, transport.PinnedHTTPSConnection)
    assert connection.destination is destination
    assert connection.timeout == 9.5
