"""Coverage-completion tests for OpenSSF evidence production edges."""

from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path

import pytest

from appguardrail_core import openssf_evidence as evidence
from appguardrail_core import openssf_report


REPOSITORY_URL = "https://github.com/ContextualWisdomLab/appguardrail"
VERIFIED_AT = "2026-08-04T10:00:00Z"


def test_redirect_guard_refuses_every_redirect() -> None:
    """The public redirect handler never creates a follow-up request."""
    guard = evidence.NoRedirect()

    assert guard.redirect_request(object(), object(), 302, "redirect", {}, "https://attacker.invalid") is None


def test_module_entrypoint_serializes_offline_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Executing the production module directly follows the same offline CLI path."""
    source = tmp_path / "projects.json"
    source.write_text("[]", encoding="utf-8")
    module_path = Path(evidence.__file__).resolve()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(module_path),
            "--repository-url",
            REPOSITORY_URL,
            "--source-json",
            str(source),
            "--verified-at",
            VERIFIED_AT,
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(str(module_path), run_name="__main__")

    assert exc_info.value.code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"][0]["evidence_status"] == "unavailable"


def test_report_url_guard_rejects_invalid_authority_syntax() -> None:
    """Malformed URL authorities cannot escape into generated Markdown links."""
    assert openssf_report._safe_project_url("https://[::1") == ""


def test_report_unknown_status_and_tier_fall_back_safely() -> None:
    """Hostile future-like metadata renders as malformed without a badge assertion."""
    section = "\n".join(
        openssf_report.render_openssf_evidence_section(
            [
                {
                    "rule_id": "openssf-best-practices-evidence",
                    "repository_url": REPOSITORY_URL,
                    "evidence_status": "future_status",
                    "badge_tier": "",
                    "verified_at": VERIFIED_AT,
                    "evidence_url": "",
                }
            ]
        )
    )

    assert "Malformed response" in section
    assert "Not verified" in section
    assert "Not available" in section


def test_report_augmentation_requires_one_summary_marker() -> None:
    """Unexpected report structure fails closed instead of silently dropping evidence."""
    with pytest.raises(ValueError, match="findings summary"):
        openssf_report.augment_buyer_diligence_report("no report marker", [])
