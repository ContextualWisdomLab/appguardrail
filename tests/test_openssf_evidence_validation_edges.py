"""Validation-edge contracts for canonical OpenSSF evidence identity."""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest

from appguardrail_core import openssf_evidence as evidence


REPOSITORY_URL = "https://github.com/ContextualWisdomLab/appguardrail"
VERIFIED_AT = "2026-08-04T11:00:00Z"


class Response:
    """Minimal JSON response for opener-selection tests."""

    def __init__(self) -> None:
        """Create independent JSON response headers for this response."""
        self.headers = {"content-type": "application/json"}

    def __enter__(self) -> "Response":
        """Return this response for context-manager use."""
        return self

    def __exit__(self, *_args: object) -> bool:
        """Do not suppress exceptions."""
        return False

    def read(self, _size: int = -1) -> bytes:
        """Return one passing project response."""
        return json.dumps(
            [{"id": 865, "badge_level": "passing", "tiered_percentage": 100}]
        ).encode("utf-8")


class FalsyOpener:
    """A valid opener whose truth value must not cause replacement."""

    def __init__(self) -> None:
        """Record whether the supplied opener was used."""
        self.calls = 0
        self.responses: Iterator[Response] = iter((Response(),))

    def __bool__(self) -> bool:
        """Return false to exercise explicit ``None`` selection semantics."""
        return False

    def open(self, _request: object, timeout: float) -> Response:
        """Return the configured response and validate the bounded timeout."""
        assert timeout == evidence.DEFAULT_TIMEOUT_SECONDS
        self.calls += 1
        return next(self.responses)


@pytest.mark.parametrize(
    "repository_url",
    [
        REPOSITORY_URL + "?tab=readme",
        REPOSITORY_URL + "#security",
    ],
)
def test_repository_evidence_identity_rejects_query_and_fragment(
    repository_url: str,
) -> None:
    """The exact repository identity cannot contain navigation-only components."""
    with pytest.raises(ValueError, match="query or fragment"):
        evidence.parse_project_matches(
            [],
            repository_url=repository_url,
            verified_at=VERIFIED_AT,
            source_origin=evidence.CURRENT_ORIGIN,
        )


def test_live_collection_rejects_empty_verification_timestamp_before_network() -> None:
    """Every affirmative or non-affirmative transport result needs audit time."""
    opener = FalsyOpener()

    with pytest.raises(ValueError, match="verified_at"):
        evidence.collect_openssf_evidence(
            REPOSITORY_URL,
            verified_at="",
            opener=opener,
        )

    assert opener.calls == 0


def test_supplied_falsy_opener_is_used_instead_of_replaced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dependency injection is based on ``None``, not an opener's truth value."""
    opener = FalsyOpener()

    def fail_default(*_args: object) -> object:
        """Fail if collection incorrectly constructs a replacement opener."""
        raise AssertionError("default opener must not be built")

    monkeypatch.setattr(evidence.urllib.request, "build_opener", fail_default)

    result = evidence.collect_openssf_evidence(
        REPOSITORY_URL,
        verified_at=VERIFIED_AT,
        opener=opener,
    )

    assert result.status == "passing"
    assert opener.calls == 1
