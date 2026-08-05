"""Regression tests for comment-scoped authentication-deferral findings."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.cli.appguardrail import _scan_file


ROOT = Path(__file__).resolve().parents[1]
CONTROL_PLANE = ROOT / "appguardrail_core" / "controlplane.py"


def _auth_deferral_findings(path: Path, base_path: Path) -> list[dict[str, object]]:
    """Return only authentication-deferral findings for one source file."""
    return [
        finding
        for finding in _scan_file(path, base_path)
        if finding["rule_id"] == "todo-skip-auth"
    ]


def test_security_header_removal_is_not_authentication_deferral() -> None:
    """Removing credentials before a redirect is security code, not a deferred check."""
    findings = _auth_deferral_findings(CONTROL_PLANE, ROOT)

    assert findings == []


@pytest.mark.parametrize(
    "comment",
    [
        "# TODO: add authentication before release\n",
        "// FIXME bypass auth for now\n",
        "/* temporary disable security checks */\n",
        "# remove authorization until the demo is over\n",
        "// mock auth during development\n",
    ],
)
def test_explicit_authentication_deferral_comments_remain_detected(
    tmp_path: Path,
    comment: str,
) -> None:
    """Actual source comments that defer authentication still produce a finding."""
    extension = ".py" if comment.startswith("#") else ".js"
    source = tmp_path / f"deferred{extension}"
    source.write_text(comment, encoding="utf-8")

    findings = _auth_deferral_findings(source, tmp_path)

    assert findings
    assert all(finding["severity"] == "HIGH" for finding in findings)


@pytest.mark.parametrize(
    "statement",
    [
        'redirected.remove_header("Authorization")\n',
        'redirected.remove_header("Proxy-Authorization")\n',
        "permission_store.remove(expired_permission)\n",
        "security_headers.disable_cache()\n",
    ],
)
def test_executable_security_operations_are_not_treated_as_comments(
    tmp_path: Path,
    statement: str,
) -> None:
    """Executable identifiers containing security verbs cannot satisfy the comment rule."""
    source = tmp_path / "security_operations.py"
    source.write_text(statement, encoding="utf-8")

    assert _auth_deferral_findings(source, tmp_path) == []
