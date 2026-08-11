"""CLI contracts for live and offline OpenSSF Best Practices evidence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from appguardrail_core import openssf_evidence as evidence

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_URL = "https://github.com/ContextualWisdomLab/appguardrail"
VERIFIED_AT = "2026-08-04T09:00:00Z"


def _source_payload() -> list[dict[str, object]]:
    """Return one saved exact-URL search response."""
    return [
        {
            "id": 865,
            "badge_level": "silver",
            "tiered_percentage": 200,
            "repo_url": REPOSITORY_URL,
        }
    ]


def test_module_cli_reads_offline_source_and_writes_standard_envelope(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Offline evidence must use the same normalized findings envelope as scans."""
    source = tmp_path / "projects.json"
    source.write_text(json.dumps(_source_payload()), encoding="utf-8")

    result = evidence.main(
        [
            "--repository-url",
            REPOSITORY_URL,
            "--source-json",
            str(source),
            "--verified-at",
            VERIFIED_AT,
        ]
    )

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "appguardrail.findings.v1"
    assert len(payload["findings"]) == 1
    finding = payload["findings"][0]
    assert finding["evidence_status"] == "silver"
    assert finding["repository_url"] == REPOSITORY_URL
    assert finding["verified_at"] == VERIFIED_AT


def test_module_cli_can_write_legacy_source_evidence_to_file(tmp_path: Path) -> None:
    """Saved legacy responses remain attributable when written for later reports."""
    source = tmp_path / "legacy.json"
    target = tmp_path / "evidence" / "findings.json"
    source.write_text(json.dumps(_source_payload()), encoding="utf-8")

    result = evidence.main(
        [
            "--repository-url",
            REPOSITORY_URL,
            "--source-json",
            str(source),
            "--source-origin",
            evidence.LEGACY_ORIGIN,
            "--verified-at",
            VERIFIED_AT,
            "--out",
            str(target),
        ]
    )

    assert result == 0
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["findings"][0]["source_origin"] == evidence.LEGACY_ORIGIN
    assert target.read_text(encoding="utf-8").endswith("\n")


def test_module_cli_collects_live_evidence_when_source_is_absent(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Live mode delegates to the fixed-origin collector and preserves its state."""
    calls: list[tuple[str, str | None]] = []

    def fake_collect(repository_url: str, *, verified_at: str | None = None):
        """Return deterministic live evidence for the command contract."""
        calls.append((repository_url, verified_at))
        return evidence.OpenSSFEvidence(
            status="passing",
            repository_url=repository_url,
            verified_at=verified_at or VERIFIED_AT,
            badge_tier="passing",
            evidence_url=f"{evidence.CURRENT_ORIGIN}/projects/865",
            project_id=865,
            tiered_percentage=100,
            source_origin=evidence.CURRENT_ORIGIN,
        )

    monkeypatch.setattr(evidence, "collect_openssf_evidence", fake_collect)

    assert (
        evidence.main(
            ["--repository-url", REPOSITORY_URL, "--verified-at", VERIFIED_AT]
        )
        == 0
    )
    assert calls == [(REPOSITORY_URL, VERIFIED_AT)]
    assert json.loads(capsys.readouterr().out)["findings"][0]["badge_tier"] == "passing"


@pytest.mark.parametrize("contents", [b"{", b"not-json", b"\xff\xfe"])
def test_module_cli_rejects_invalid_local_json_or_utf8(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    contents: bytes,
) -> None:
    """Invalid local files are operator errors rather than fabricated evidence states."""
    source = tmp_path / "invalid.json"
    source.write_bytes(contents)

    result = evidence.main(
        ["--repository-url", REPOSITORY_URL, "--source-json", str(source)]
    )

    assert result == 1
    assert "invalid JSON or UTF-8" in capsys.readouterr().err


def test_module_cli_rejects_oversized_offline_evidence(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Offline evidence ingestion has the same response-size boundary as live mode."""
    source = tmp_path / "oversized.json"
    source.write_bytes(b" " * (evidence.MAX_RESPONSE_BYTES + 1))

    result = evidence.main(
        ["--repository-url", REPOSITORY_URL, "--source-json", str(source)]
    )

    assert result == 1
    assert "exceeds" in capsys.readouterr().err.lower()


@pytest.mark.parametrize(
    ("arguments", "detail"),
    [
        (
            ["--repository-url", "file:///tmp/repo", "--verified-at", VERIFIED_AT],
            "repository URL",
        ),
        (
            ["--repository-url", REPOSITORY_URL, "--verified-at", "2026-08-04"],
            "verified_at",
        ),
    ],
)
def test_module_cli_reports_invalid_identity_without_a_traceback(
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
    detail: str,
) -> None:
    """Invalid operator input returns one concise non-zero command result."""
    assert evidence.main(arguments) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Invalid OpenSSF evidence input:" in captured.err
    assert detail in captured.err


def test_module_cli_reports_source_and_output_io_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Unreadable inputs and unwritable outputs return concise non-zero results."""
    missing = tmp_path / "missing.json"
    assert (
        evidence.main(
            ["--repository-url", REPOSITORY_URL, "--source-json", str(missing)]
        )
        == 1
    )
    assert "cannot read" in capsys.readouterr().err.lower()

    source = tmp_path / "source.json"
    source.write_text("[]", encoding="utf-8")

    def fail_write(*_args: object, **_kwargs: object) -> int:
        """Raise the file-system error used by the output-path contract."""
        raise OSError("read-only")

    monkeypatch.setattr(evidence.Path, "write_text", fail_write)
    assert (
        evidence.main(
            [
                "--repository-url",
                REPOSITORY_URL,
                "--source-json",
                str(source),
                "--out",
                str(tmp_path / "out.json"),
            ]
        )
        == 1
    )
    assert "cannot write" in capsys.readouterr().err.lower()


def test_module_cli_requires_repository_url() -> None:
    """The evidence identity is required in both live and offline modes."""
    with pytest.raises(SystemExit):
        evidence.parse_args([])


def test_package_publishes_a_modular_openssf_console_script() -> None:
    """Standalone and MSA users receive a dedicated installed evidence command."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert (
        'appguardrail-openssf-evidence = "appguardrail_core.openssf_evidence:main"'
        in pyproject
    )
