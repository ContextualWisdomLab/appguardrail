"""CLI integration contracts for bearer-authenticated pinned HTTPS delivery."""

from __future__ import annotations

import json

import pytest

from appguardrail_core.pinned_https import PinnedHTTPSFailure, PinnedHTTPSResponse
from scanner.cli import appguardrail as cli


@pytest.mark.parametrize(
    "url",
    [
        "http://api.example.com",
        "https://user:secret@api.example.com/root",
        "https://api.example.com/root?token=secret-query",
        "https://api.example.com/root#secret-fragment",
        "https://[broken",
    ],
)
def test_push_findings_requires_unambiguous_public_https_before_transport(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    url: str,
) -> None:
    """Unsafe base identities are rejected without echoing attacker-controlled text."""
    monkeypatch.setenv("APPGUARDRAIL_API_KEY", "credential-value")
    monkeypatch.setattr(
        cli,
        "post_json_pinned_https",
        lambda *_args, **_kwargs: pytest.fail("transport must not run"),
    )

    cli._push_findings(url, [])

    captured = capsys.readouterr()
    assert "public HTTPS URL" in captured.err
    assert url not in captured.err
    assert "secret" not in captured.err


def test_push_findings_sends_normalized_payload_through_pinned_transport(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The CLI supplies one bounded authenticated request and renders its receipt."""
    observed: dict[str, object] = {}

    def deliver(
        url: str,
        payload: dict[str, object],
        *,
        headers: dict[str, str],
        timeout: float,
    ) -> PinnedHTTPSResponse:
        observed.update(
            url=url,
            payload=payload,
            headers=headers,
            timeout=timeout,
        )
        return PinnedHTTPSResponse(
            status=201,
            reason="Created",
            headers=(("Content-Type", "application/json"),),
            body=json.dumps({"id": 41, "new_blocking": 2}).encode("utf-8"),
        )

    monkeypatch.setenv("APPGUARDRAIL_API_KEY", "credential-value")
    monkeypatch.setenv("GITHUB_REPOSITORY", "ContextualWisdomLab/appguardrail")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setattr(cli, "post_json_pinned_https", deliver)

    cli._push_findings(
        "https://api.example.com/root/",
        [
            {
                "rule_id": "example-rule",
                "severity": "HIGH",
                "message": "example",
                "file": "src/app.py",
                "line": 1,
                "snippet": "",
                "source": "test",
            }
        ],
    )

    assert observed["url"] == "https://api.example.com/root/api/v1/scans"
    assert observed["timeout"] == 15
    headers = observed["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"] == "Bearer credential-value"
    assert headers["Content-Type"] == "application/json"
    payload = observed["payload"]
    assert isinstance(payload, dict)
    assert payload["repo"] == "ContextualWisdomLab/appguardrail"
    assert payload["commit"] == "a" * 40
    assert len(payload["findings"]) == 1
    captured = capsys.readouterr()
    assert "Pushed scan #41" in captured.out
    assert "2 newly deploy-blocking" in captured.out


def test_push_findings_reports_non_success_without_copying_response_body(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A remote error exposes only its status and never an untrusted response body."""
    monkeypatch.setenv("APPGUARDRAIL_API_KEY", "credential-value")
    monkeypatch.setattr(
        cli,
        "post_json_pinned_https",
        lambda *_args, **_kwargs: PinnedHTTPSResponse(
            status=503,
            reason="Service Unavailable",
            headers=(),
            body=b"internal tenant data",
        ),
    )

    cli._push_findings("https://api.example.com", [])

    captured = capsys.readouterr()
    assert "(503)" in captured.err
    assert "internal tenant data" not in captured.err


def test_push_findings_bounds_transport_and_response_parse_failures(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Network and malformed receipt failures remain non-secret operational messages."""
    monkeypatch.setenv("APPGUARDRAIL_API_KEY", "credential-value")

    def fail_transport(*_args: object, **_kwargs: object) -> PinnedHTTPSResponse:
        raise PinnedHTTPSFailure("private implementation detail")

    monkeypatch.setattr(cli, "post_json_pinned_https", fail_transport)
    cli._push_findings("https://api.example.com", [])
    first = capsys.readouterr()
    assert "Control-plane push failed" in first.err
    assert "private implementation detail" not in first.err

    monkeypatch.setattr(
        cli,
        "post_json_pinned_https",
        lambda *_args, **_kwargs: PinnedHTTPSResponse(
            status=200,
            reason="OK",
            headers=(),
            body=b"not-json",
        ),
    )
    cli._push_findings("https://api.example.com", [])
    second = capsys.readouterr()
    assert "invalid response" in second.err.lower()


@pytest.mark.parametrize(
    "receipt",
    [
        {"id": "\x1b[31mforged", "new_blocking": 0},
        {"id": 0, "new_blocking": 0},
        {"id": True, "new_blocking": 0},
        {"id": 41, "new_blocking": "\x1b[31mforged"},
        {"id": 41, "new_blocking": -1},
        {"id": 41, "new_blocking": True},
    ],
)
def test_push_findings_rejects_untrusted_receipt_metadata(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    receipt: dict[str, object],
) -> None:
    """Untrusted response fields cannot become terminal output or forged receipts."""
    monkeypatch.setenv("APPGUARDRAIL_API_KEY", "credential-value")
    monkeypatch.setattr(
        cli,
        "post_json_pinned_https",
        lambda *_args, **_kwargs: PinnedHTTPSResponse(
            status=201,
            reason="Created",
            headers=(),
            body=json.dumps(receipt).encode("utf-8"),
        ),
    )

    cli._push_findings("https://api.example.com", [])

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "invalid response" in captured.err.lower()
    assert "forged" not in captured.err
    assert "\x1b" not in captured.err
