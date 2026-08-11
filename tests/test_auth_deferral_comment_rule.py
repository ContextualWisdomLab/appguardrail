"""Regression contracts for comment-scoped authentication-deferral findings."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.cli.appguardrail import _scan_file


def _auth_deferral_findings(path: Path, base_path: Path) -> list[dict[str, object]]:
    """Return only findings produced by the packaged authentication-deferral rule."""
    return [
        finding
        for finding in _scan_file(path, base_path)
        if finding["rule_id"] == "todo-skip-auth"
    ]


@pytest.mark.parametrize(
    ("filename", "source"),
    [
        (
            "calculation.py",
            "result = (\n    * todo\n    * auth\n)\n",
        ),
        (
            "calculation.js",
            "const result = left\n  * todo\n  * auth;\n",
        ),
        (
            "security.py",
            "authorization_headers = remove_sensitive_headers(headers)\n",
        ),
        (
            "security.js",
            "const sanitized = removeAuthorization(headers);\n",
        ),
    ],
)
def test_executable_code_is_not_misclassified_as_an_auth_deferral_comment(
    tmp_path: Path,
    filename: str,
    source: str,
) -> None:
    """Executable stars and security hardening operations never create HIGH findings."""
    target = tmp_path / filename
    target.write_text(source, encoding="utf-8")

    assert _auth_deferral_findings(target, tmp_path) == []


@pytest.mark.parametrize(
    ("filename", "comment"),
    [
        ("app.py", "# TODO: add authentication before release\n"),
        ("app.py", "# remove authorization until the demo is over\n"),
        ("app.js", "// FIXME bypass auth for now\n"),
        ("app.js", "// mock auth during development\n"),
        (
            "app.js",
            "/*\n * TODO: restore authentication before deployment\n */\n",
        ),
        (
            "app.js",
            "/* temporary disable security checks for the prototype */\n",
        ),
        (
            "app.js",
            "/*\n * release notes\n   // TODO: restore authentication before deployment\n */\n",
        ),
    ],
)
def test_explicit_line_and_block_comment_deferrals_remain_detected(
    tmp_path: Path,
    filename: str,
    comment: str,
) -> None:
    """Real Python and JavaScript comments retain the intended security signal."""
    target = tmp_path / filename
    target.write_text(comment, encoding="utf-8")

    findings = _auth_deferral_findings(target, tmp_path)

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["context"] == "app-code"
