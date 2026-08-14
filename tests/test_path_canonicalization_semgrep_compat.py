"""Semgrep-compatibility regressions for the path canonicalization detector."""

from scanner.cli.appguardrail import SCAN_RULES

_RULE_ID = "python-url-path-traversal-validate-before-canonicalize"
_SEMGREP_PATTERN_REGEX_BUDGET = 600


def test_path_canonicalization_patterns_stay_within_semgrep_regex_budget() -> None:
    """Keep each shipped regex below the size that failed Semgrep validation."""
    patterns = tuple(
        rule["pattern"].pattern for rule in SCAN_RULES if rule["id"] == _RULE_ID
    )

    assert len(patterns) == 2
    assert all(
        len(pattern) <= _SEMGREP_PATTERN_REGEX_BUDGET for pattern in patterns
    ), (
        "path canonicalization patterns must stay compact enough for the Semgrep "
        "engine used by the required SAST gate"
    )
