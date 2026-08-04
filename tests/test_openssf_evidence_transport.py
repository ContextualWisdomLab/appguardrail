"""Transport contracts for fixed-origin OpenSSF Best Practices collection."""

from __future__ import annotations

import io
import json
import urllib.error
from collections.abc import Iterator
from email.message import Message

import pytest

from appguardrail_core import openssf_evidence as evidence


REPOSITORY_URL = "https://github.com/ContextualWisdomLab/appguardrail"
VERIFIED_AT = "2026-08-04T07:00:00Z"


class Response:
    """Small urllib-compatible response with bounded reads and JSON headers."""

    def __init__(self, payload: bytes, content_type: str = "application/json") -> None:
        """Store response bytes and a content-type header."""
        self.payload = payload
        self.headers = {"content-type": content_type}

    def __enter__(self) -> "Response":
        """Return this response for context-manager use."""
        return self

    def __exit__(self, *_args: object) -> bool:
        """Do not suppress exceptions."""
        return False

    def read(self, size: int = -1) -> bytes:
        """Return at most the requested number of bytes."""
        return self.payload if size < 0 else self.payload[:size]


class SequenceOpener:
    """Return or raise configured outcomes and record requested URLs."""

    def __init__(self, *outcomes: object) -> None:
        """Store outcomes in request order."""
        self.outcomes: Iterator[object] = iter(outcomes)
        self.urls: list[str] = []
        self.timeouts: list[float] = []

    def open(self, request: object, timeout: float) -> Response:
        """Return the next response or raise the configured exception."""
        self.urls.append(request.full_url)
        self.timeouts.append(timeout)
        outcome = next(self.outcomes)
        if isinstance(outcome, BaseException):
            raise outcome
        assert isinstance(outcome, Response)
        return outcome


def _json_response(payload: object) -> Response:
    """Encode one JSON payload as an HTTP response."""
    return Response(json.dumps(payload).encode("utf-8"))


def _http_error(status: int) -> urllib.error.HTTPError:
    """Return an HTTP error without carrying an untrusted response body."""
    headers = Message()
    return urllib.error.HTTPError(
        f"https://www.bestpractices.dev/projects.json?url={REPOSITORY_URL}",
        status,
        "status",
        headers,
        io.BytesIO(b"untrusted response body"),
    )


def test_current_origin_success_does_not_query_legacy() -> None:
    """A current-origin match is authoritative and avoids an unnecessary fallback."""
    opener = SequenceOpener(
        _json_response([{"id": 865, "badge_level": "gold", "tiered_percentage": 300}])
    )

    result = evidence.collect_openssf_evidence(
        REPOSITORY_URL,
        verified_at=VERIFIED_AT,
        opener=opener,
        timeout=9.5,
    )

    assert result.status == "gold"
    assert result.source_origin == evidence.CURRENT_ORIGIN
    assert len(opener.urls) == 1
    assert opener.urls[0].startswith(f"{evidence.CURRENT_ORIGIN}/projects.json?")
    assert "url=https%3A%2F%2Fgithub.com%2FContextualWisdomLab%2Fappguardrail" in opener.urls[0]
    assert opener.timeouts == [9.5]


def test_valid_empty_current_result_falls_back_to_legacy() -> None:
    """Legacy evidence is queried only after a valid empty current-origin search."""
    opener = SequenceOpener(
        _json_response([]),
        _json_response([{"id": 42, "badge_level": "passing", "tiered_percentage": 100}]),
    )

    result = evidence.collect_openssf_evidence(
        REPOSITORY_URL,
        verified_at=VERIFIED_AT,
        opener=opener,
    )

    assert result.status == "passing"
    assert result.source_origin == evidence.LEGACY_ORIGIN
    assert opener.urls[1].startswith(f"{evidence.LEGACY_ORIGIN}/projects.json?")


def test_empty_current_and_legacy_results_remain_unavailable() -> None:
    """Two empty public searches still cannot prove that a project is unregistered."""
    opener = SequenceOpener(_json_response([]), _json_response([]))

    result = evidence.collect_openssf_evidence(
        REPOSITORY_URL,
        verified_at=VERIFIED_AT,
        opener=opener,
    )

    assert result.status == "unavailable"
    assert result.reason == "no_matching_public_project_current_or_legacy"
    assert result.source_origin == evidence.LEGACY_ORIGIN


@pytest.mark.parametrize("status", [401, 403])
def test_permission_responses_are_permission_limited(status: int) -> None:
    """Permission responses remain distinct from absence of public evidence."""
    result = evidence.collect_openssf_evidence(
        REPOSITORY_URL,
        verified_at=VERIFIED_AT,
        opener=SequenceOpener(_http_error(status)),
    )

    assert result.status == "permission_limited"
    assert result.reason == f"http_{status}"


@pytest.mark.parametrize("status", [404, 429, 500, 503])
def test_unavailable_http_responses_do_not_claim_no_registration(status: int) -> None:
    """Missing, throttled, and failed services are classified as unavailable evidence."""
    opener = SequenceOpener(_http_error(status))

    result = evidence.collect_openssf_evidence(
        REPOSITORY_URL,
        verified_at=VERIFIED_AT,
        opener=opener,
    )

    assert result.status == "unavailable"
    assert result.reason == f"http_{status}"
    assert len(opener.urls) == 1


def test_redirect_response_is_rejected_without_origin_following() -> None:
    """Authenticated evidence collection must not follow unexpected redirects."""
    result = evidence.collect_openssf_evidence(
        REPOSITORY_URL,
        verified_at=VERIFIED_AT,
        opener=SequenceOpener(_http_error(302)),
    )

    assert result.status == "malformed"
    assert result.reason == "unexpected_redirect"


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (Response(b"not-json"), "invalid_json"),
        (_json_response({"projects": []}), "payload_not_array"),
        (Response(b"[]", "text/html"), "unexpected_content_type"),
        (Response(b"x" * (1_000_001)), "response_too_large"),
    ],
)
def test_invalid_or_oversized_responses_are_malformed(
    response: Response,
    reason: str,
) -> None:
    """Malformed service responses stay auditable and never become badge claims."""
    result = evidence.collect_openssf_evidence(
        REPOSITORY_URL,
        verified_at=VERIFIED_AT,
        opener=SequenceOpener(response),
    )

    assert result.status == "malformed"
    assert result.reason == reason


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        (urllib.error.URLError("dns"), "network_error"),
        (TimeoutError("slow"), "timeout"),
        (OSError("socket"), "network_error"),
    ],
)
def test_network_failures_are_unavailable_without_exception_details(
    failure: BaseException,
    reason: str,
) -> None:
    """Network failures expose a bounded category rather than raw exception details."""
    result = evidence.collect_openssf_evidence(
        REPOSITORY_URL,
        verified_at=VERIFIED_AT,
        opener=SequenceOpener(failure),
    )

    assert result.status == "unavailable"
    assert result.reason == reason
    assert "dns" not in result.reason


def test_default_timestamp_and_opener_are_constructed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The public collector supplies deterministic helpers when callers omit them."""
    opener = SequenceOpener(
        _json_response([{"id": 9, "badge_level": "silver", "tiered_percentage": 200}])
    )
    monkeypatch.setattr(evidence, "_utc_timestamp", lambda: VERIFIED_AT)
    monkeypatch.setattr(evidence.urllib.request, "build_opener", lambda *_handlers: opener)

    result = evidence.collect_openssf_evidence(REPOSITORY_URL)

    assert result.status == "silver"
    assert result.verified_at == VERIFIED_AT


@pytest.mark.parametrize("timeout", [0, -1, True])
def test_timeout_must_be_a_positive_number(timeout: object) -> None:
    """Invalid timeouts are rejected before any network operation."""
    with pytest.raises(ValueError, match="timeout"):
        evidence.collect_openssf_evidence(
            REPOSITORY_URL,
            verified_at=VERIFIED_AT,
            opener=SequenceOpener(),
            timeout=timeout,
        )
