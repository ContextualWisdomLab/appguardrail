"""Semgrep-compatibility regressions for the path canonicalization detector."""

import shutil
import subprocess
from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES

_RULE_ID = "python-url-path-traversal-validate-before-canonicalize"
_SEMGREP_VERSION = "1.170.0"
_SEMGREP_PATTERN_REGEX_BUDGET = 500
_RULE_CONFIG = (
    Path(__file__).resolve().parents[1] / "scanner" / "rules" / "path_canonicalization.yml"
)


def _validate_with_semgrep(semgrep_binary: str) -> None:
    """Validate the shipped detector with the exact compatibility engine."""
    version = subprocess.run(
        [semgrep_binary, "--version"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert version == _SEMGREP_VERSION, (
        f"expected Semgrep {_SEMGREP_VERSION}, got {version or 'no version output'}"
    )
    subprocess.run(
        [
            semgrep_binary,
            "--metrics",
            "off",
            "--validate",
            "--config",
            str(_RULE_CONFIG),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def test_path_canonicalization_patterns_stay_within_semgrep_regex_budget() -> None:
    """Keep each shipped regex below the parser-failure complexity boundary."""
    patterns = tuple(
        rule["pattern"].pattern for rule in SCAN_RULES if rule["id"] == _RULE_ID
    )

    assert len(patterns) == 2
    assert all(
        len(pattern) <= _SEMGREP_PATTERN_REGEX_BUDGET for pattern in patterns
    ), (
        "path canonicalization patterns must stay compact enough for Semgrep "
        f"{_SEMGREP_VERSION}"
    )


def test_path_canonicalization_config_parses_with_semgrep_1_170_0() -> None:
    """Propagate real Semgrep parser failures when the exact engine is present."""
    semgrep_binary = shutil.which("semgrep")
    if semgrep_binary is None:
        import pytest

        pytest.skip(
            "Semgrep is exercised by the dedicated pinned-container job in Tests CI"
        )
    _validate_with_semgrep(semgrep_binary)
