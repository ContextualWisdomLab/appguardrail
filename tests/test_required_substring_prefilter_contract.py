"""Security-contract tests for the required-substring scanner prefilter."""

import re
from unittest.mock import patch

import pytest

from scanner.cli.appguardrail import _scan_file

_RULE_ID = "required-substring-prefilter-contract"


def _rule(required_substrings, pattern):
    """Build one controlled scanner rule with the production prefilter field."""

    return {
        "id": _RULE_ID,
        "pattern": pattern,
        "severity": "HIGH",
        "message": "controlled scanner finding [CWE-20 - Improper Input Validation]",
        "extensions": [".py"],
        "required_substrings": tuple(required_substrings),
    }


def _scan(tmp_path, content, required_substrings, pattern):
    """Execute the real file-scanner boundary with one controlled rule."""

    source_file = tmp_path / "source.py"
    source_file.write_text(content, encoding="utf-8")
    with patch(
        "scanner.cli.appguardrail.SCAN_RULES",
        [_rule(required_substrings, pattern)],
    ):
        return _scan_file(source_file, tmp_path)


@pytest.mark.parametrize(
    "required_substrings",
    [
        ("missing", "present_a", "present_b"),
        ("present_a", "missing", "present_b"),
        ("present_a", "present_b", "missing"),
    ],
)
def test_required_substring_prefilter_skips_rule_when_any_literal_is_missing(
    tmp_path, required_substrings
):
    """A missing first, middle, or last required literal must skip regex work."""

    class ExplodingPattern:
        def finditer(self, _content):
            raise AssertionError("regex must not run after prefilter rejection")

    findings = _scan(
        tmp_path,
        "present_a = 1\npresent_b = danger_call()\n",
        required_substrings,
        ExplodingPattern(),
    )

    assert findings == []


def test_required_substring_prefilter_preserves_finding_when_all_literals_exist(tmp_path):
    """All-present prefiltering must preserve the no-prefilter finding exactly."""

    content = "present_a = 1\npresent_b = danger_call()\n"
    pattern = re.compile(r"danger_call\(\)")

    no_prefilter = _scan(tmp_path, content, (), pattern)
    with_prefilter = _scan(
        tmp_path,
        content,
        ("present_a", "present_b", "danger_call"),
        pattern,
    )

    assert len(no_prefilter) == 1
    assert with_prefilter == no_prefilter
    assert with_prefilter[0]["rule_id"] == _RULE_ID
