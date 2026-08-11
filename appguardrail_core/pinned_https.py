"""Deliver credential-bearing JSON over DNS-pinned public HTTPS connections.

The transport closes the gap between validating a hostname and later asking the
operating system to resolve that hostname again for the actual TCP connection.
Each request hop resolves exactly once, rejects every non-global answer, and
connects only to the captured socket addresses while retaining the original
hostname for TLS Server Name Indication and certificate identity verification.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_MAX_RESPONSE_BYTES = 1_000_000
_REDIRECT_STATUSES = frozenset({307, 308})
_SENSITIVE_HEADERS = frozenset({"authorization", "proxy-authorization"})
_FORBIDDEN_CALLER_HEADERS = frozenset(
    {"connection", "content-length", "host", "transfer-encoding"}
)
_HEADER_NAME_RE = re.compile(r"\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


class PinnedHTTPSFailure(RuntimeError):
    """Report one bounded DNS-pinned HTTPS transport failure."""


class DestinationValidationError(PinnedHTTPSFailure):
    """Report an invalid or non-public credential-bearing destination."""


@dataclass(frozen=True)
class ResolvedAddress:
    """One validated TCP address captured from a single resolver decision."""

    family: int
    socket_type: int
    protocol: int
    socket_address: tuple[Any, ...]
    ip_address: str


@dataclass(frozen=True)
class HTTPSDestination:
    """A canonical HTTPS origin and its immutable validated address set."""

    url: str
    hostname: str
    port: int
    request_target: str
    addresses: tuple[ResolvedAddress, ...]

    @property
    def origin(self) -> tuple[str, str, int]:
        """Return the normalized origin used for redirect credential scoping."""
        return ("https", self.hostname, self.port)


@dataclass(frozen=True)
class PinnedHTTPSResponse:
    """A bounded HTTP response returned by the pinned transport."""

    status: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def get_header(self, name: str) -> str | None:
        """Return the first matching response header without case sensitivity."""
        expected = name.lower()
        for header_name, value in self.headers:
            if header_name.lower() == expected:
                return value
        return None


Resolver = Callable[
    [str, int, int, int, int],
    Sequence[tuple[int, int, int, str, tuple[Any, ...]]],
]
SocketFactory = Callable[[int, int, int], Any]
ConnectionFactory = Callable[[HTTPSDestination, float], Any]


def _has_control_character(value: str) -> bool:
    """Return whether a URL or header contains an ASCII control character."""
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def _is_permitted_global_address(
    value: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Return whether an address is globally routable and not IPv4-mapped."""
    if isinstance(value, ipaddress.IPv6Address) and value.ipv4_mapped is not None:
        return False
    return not (
        value.is_loopback
        or value.is_private
        or value.is_link_local
        or value.is_multicast
        or value.is_unspecified
        or value.is_reserved
        or not value.is_global
    )


def _canonical_hostname(hostname: str) -> str:
    """Return a lowercase ASCII service identity suitable for TLS verification."""
    candidate = hostname.strip().rstrip(".")
    if not candidate or "%" in candidate or _has_control_character(candidate):
        raise DestinationValidationError("HTTPS destination has an invalid hostname")
    try:
        literal = ipaddress.ip_address(candidate)
    except ValueError:
        try:
            candidate = candidate.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise DestinationValidationError(
                "HTTPS destination hostname is not valid IDNA"
            ) from exc
        if not candidate or len(candidate) > 253:
            raise DestinationValidationError("HTTPS destination hostname is invalid")
        return candidate
    if not _is_permitted_global_address(literal):
        raise DestinationValidationError(
            "HTTPS destination resolved to a non-global address"
        )
    return literal.compressed.lower()


def _quoted_request_target(parts: urllib.parse.SplitResult) -> str:
    """Return an origin-form request target while preserving valid percent escapes."""
    path = urllib.parse.quote(
        parts.path or "/",
        safe="/%:@!$&'()*+,;=-._~",
    )
    if not path.startswith("/"):
        path = "/" + path
    if not parts.query:
        return path
    query = urllib.parse.quote(
        parts.query,
        safe="/%?:@!$&'()*+,;=-._~",
    )
    return f"{path}?{query}"


def _canonical_url(hostname: str, port: int, request_target: str) -> str:
    """Build the canonical absolute URL retained for relative redirect resolution."""
    authority_host = f"[{hostname}]" if ":" in hostname else hostname
    authority = authority_host if port == 443 else f"{authority_host}:{port}"
    return f"https://{authority}{request_target}"


def _resolved_address(
    result: tuple[int, int, int, str, tuple[Any, ...]],
    *,
    expected_port: int,
) -> ResolvedAddress | None:
    """Validate one getaddrinfo result and return its immutable representation."""
    try:
        family, socket_type, protocol, _canonical_name, socket_address = result
    except (TypeError, ValueError):
        return None
    if family not in {socket.AF_INET, socket.AF_INET6}:
        return None
    if socket_type != socket.SOCK_STREAM or protocol not in {0, socket.IPPROTO_TCP}:
        return None
    if not isinstance(socket_address, tuple) or len(socket_address) < 2:
        return None
    if socket_address[1] != expected_port:
        raise DestinationValidationError("resolver returned an unexpected port")
    raw_ip = str(socket_address[0])
    if "%" in raw_ip:
        raise DestinationValidationError("zone-scoped addresses are not permitted")
    try:
        parsed_ip = ipaddress.ip_address(raw_ip)
    except ValueError as exc:
        raise DestinationValidationError(
            "resolver returned an invalid IP address"
        ) from exc
    if not _is_permitted_global_address(parsed_ip):
        raise DestinationValidationError(
            "HTTPS destination resolved to a non-global address"
        )
    if (
        family == socket.AF_INET6
        and len(socket_address) >= 4
        and socket_address[3] != 0
    ):
        raise DestinationValidationError("zone-scoped addresses are not permitted")
    return ResolvedAddress(
        family=family,
        socket_type=socket.SOCK_STREAM,
        protocol=socket.IPPROTO_TCP,
        socket_address=socket_address,
        ip_address=parsed_ip.compressed,
    )


def resolve_public_https_destination(
    url: str,
    *,
    resolver: Resolver = socket.getaddrinfo,
) -> HTTPSDestination:
    """Resolve one strict public HTTPS destination exactly once.

    Every returned TCP address must be globally routable. A mixed answer set is
    rejected in full instead of silently selecting only the public subset.
    """
    if not isinstance(url, str) or not url or _has_control_character(url):
        raise DestinationValidationError("HTTPS destination URL is invalid")
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise DestinationValidationError("HTTPS destination URL is invalid") from exc
    if parts.scheme.lower() != "https":
        raise DestinationValidationError("control-plane delivery requires public HTTPS")
    if parts.username is not None or parts.password is not None:
        raise DestinationValidationError(
            "HTTPS destination must not contain credentials"
        )
    if parts.fragment:
        raise DestinationValidationError(
            "HTTPS destination must not contain a fragment"
        )
    if not parts.hostname:
        raise DestinationValidationError("HTTPS destination must include a hostname")
    hostname = _canonical_hostname(parts.hostname)
    try:
        parsed_port = parts.port
        port = 443 if parsed_port is None else parsed_port
    except ValueError as exc:
        raise DestinationValidationError("HTTPS destination port is invalid") from exc
    if isinstance(port, bool) or not 1 <= port <= 65535:
        raise DestinationValidationError("HTTPS destination port is invalid")
    request_target = _quoted_request_target(parts)

    try:
        answers = resolver(
            hostname,
            port,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
        )
    except (OSError, socket.gaierror) as exc:
        raise DestinationValidationError("HTTPS destination resolution failed") from exc

    validated: list[ResolvedAddress] = []
    seen: set[tuple[int, int, int, tuple[Any, ...]]] = set()
    for result in answers:
        address = _resolved_address(result, expected_port=port)
        if address is None:
            continue
        identity = (
            address.family,
            address.socket_type,
            address.protocol,
            address.socket_address,
        )
        if identity not in seen:
            seen.add(identity)
            validated.append(address)
    if not validated:
        raise DestinationValidationError(
            "HTTPS destination resolution returned no TCP addresses"
        )
    canonical_url = _canonical_url(hostname, port, request_target)
    return HTTPSDestination(
        url=canonical_url,
        hostname=hostname,
        port=port,
        request_target=request_target,
        addresses=tuple(validated),
    )


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect an HTTPS request only to a prevalidated immutable address set."""

    def __init__(
        self,
        destination: HTTPSDestination,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        context: ssl.SSLContext | Any | None = None,
        socket_factory: SocketFactory = socket.socket,
    ) -> None:
        """Create a connection retaining the URL hostname for TLS verification."""
        super().__init__(
            destination.hostname,
            destination.port,
            timeout=timeout,
            context=context,
        )
        self.destination = destination
        self._socket_factory = socket_factory

    def connect(self) -> None:
        """Open TCP directly to the validated addresses and then negotiate TLS."""
        if self._tunnel_host:
            raise OSError("HTTP tunneling is not supported by pinned HTTPS")
        last_error: OSError | None = None
        for address in self.destination.addresses:
            raw_socket = None
            try:
                raw_socket = self._socket_factory(
                    address.family,
                    address.socket_type,
                    address.protocol,
                )
                raw_socket.settimeout(self.timeout)
                if self.source_address:
                    raw_socket.bind(self.source_address)
                raw_socket.connect(address.socket_address)
                self.sock = self._context.wrap_socket(
                    raw_socket,
                    server_hostname=self.destination.hostname,
                )
                return
            except OSError as exc:
                last_error = exc
                if raw_socket is not None:
                    raw_socket.close()
        if last_error is not None:
            raise last_error
        raise OSError("HTTPS destination has no validated addresses")


def _validated_bound(
    value: int | float,
    *,
    name: str,
    allow_zero: bool,
    integer_only: bool,
) -> int | float:
    """Validate one resource bound before serialization, resolution, or I/O."""
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a valid resource bound")
    if integer_only and not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not integer_only and not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be numeric")
    if value < 0 or (not allow_zero and value == 0):
        raise ValueError(f"{name} must be positive")
    return value


def _prepared_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    """Validate caller headers and install deterministic JSON defaults."""
    prepared: dict[str, str] = {}
    observed_names: set[str] = set()
    for name, value in (headers or {}).items():
        if not isinstance(name, str) or not _HEADER_NAME_RE.fullmatch(name):
            raise ValueError("HTTP header name is invalid")
        if not isinstance(value, str) or _has_control_character(value):
            raise ValueError("HTTP header value is invalid")
        lowered = name.lower()
        if lowered in _FORBIDDEN_CALLER_HEADERS:
            raise ValueError(f"caller cannot set the {name} header")
        if lowered in observed_names:
            raise ValueError("duplicate HTTP header names are not permitted")
        observed_names.add(lowered)
        prepared[name] = value
    if "content-type" not in observed_names:
        prepared["Content-Type"] = "application/json"
    if "accept" not in observed_names:
        prepared["Accept"] = "application/json"
    return prepared


def _without_sensitive_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Remove credential headers using their actual case-preserved names."""
    return {
        name: value
        for name, value in headers.items()
        if name.lower() not in _SENSITIVE_HEADERS
    }


def _default_connection_factory(
    destination: HTTPSDestination,
    timeout: float,
) -> PinnedHTTPSConnection:
    """Create the production pinned HTTPS connection for one validated hop."""
    return PinnedHTTPSConnection(destination, timeout=timeout)


def post_json_pinned_https(
    url: str,
    payload: Any,
    *,
    headers: Mapping[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    resolver: Resolver = socket.getaddrinfo,
    connection_factory: ConnectionFactory | None = None,
) -> PinnedHTTPSResponse:
    """POST JSON through strict DNS-pinned HTTPS with bounded redirects.

    Only method-preserving 307 and 308 redirects are followed. Sensitive
    authorization headers remain on the same normalized HTTPS origin and are
    stripped case-insensitively before any cross-origin request.
    """
    timeout = float(
        _validated_bound(
            timeout,
            name="timeout",
            allow_zero=False,
            integer_only=False,
        )
    )
    max_redirects = int(
        _validated_bound(
            max_redirects,
            name="max_redirects",
            allow_zero=True,
            integer_only=True,
        )
    )
    max_response_bytes = int(
        _validated_bound(
            max_response_bytes,
            name="max_response_bytes",
            allow_zero=False,
            integer_only=True,
        )
    )
    request_headers = _prepared_headers(headers)
    try:
        body = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise PinnedHTTPSFailure("JSON serialization failed") from exc

    destination = resolve_public_https_destination(url, resolver=resolver)
    create_connection = connection_factory or _default_connection_factory
    redirects_followed = 0

    while True:
        connection = create_connection(destination, timeout)
        response = None
        try:
            connection.request(
                "POST",
                destination.request_target,
                body=body,
                headers=request_headers,
            )
            response = connection.getresponse()
            response_body = response.read(max_response_bytes + 1)
            if len(response_body) > max_response_bytes:
                raise PinnedHTTPSFailure(
                    f"HTTPS response exceeds {max_response_bytes} bytes"
                )
            result = PinnedHTTPSResponse(
                status=int(response.status),
                reason=str(response.reason or ""),
                headers=tuple(
                    (str(name), str(value)) for name, value in response.getheaders()
                ),
                body=response_body,
            )
        except PinnedHTTPSFailure:
            raise
        except (OSError, http.client.HTTPException) as exc:
            raise PinnedHTTPSFailure("pinned HTTPS delivery failed") from exc
        finally:
            connection.close()

        if not 300 <= result.status < 400:
            return result
        if result.status not in _REDIRECT_STATUSES:
            raise PinnedHTTPSFailure(f"unsupported redirect status {result.status}")
        if redirects_followed >= max_redirects:
            raise PinnedHTTPSFailure("too many redirects")
        location = result.get_header("Location")
        if location is None or not location.strip():
            raise PinnedHTTPSFailure("redirect response is missing Location")
        if _has_control_character(location):
            raise PinnedHTTPSFailure("redirect Location is invalid")
        redirected_url = urllib.parse.urljoin(destination.url, location)
        redirected_destination = resolve_public_https_destination(
            redirected_url,
            resolver=resolver,
        )
        if redirected_destination.origin != destination.origin:
            request_headers = _without_sensitive_headers(request_headers)
        destination = redirected_destination
        redirects_followed += 1


__all__ = [
    "DEFAULT_MAX_REDIRECTS",
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "DestinationValidationError",
    "HTTPSDestination",
    "PinnedHTTPSConnection",
    "PinnedHTTPSFailure",
    "PinnedHTTPSResponse",
    "ResolvedAddress",
    "post_json_pinned_https",
    "resolve_public_https_destination",
]
