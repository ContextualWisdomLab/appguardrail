"""Regression contracts for trusted PyPI release-source integrity."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    """Return one repository file as UTF-8 text."""

    return (ROOT / path).read_text(encoding="utf-8")


def _squash_whitespace(text: str) -> str:
    """Return semantic prose with formatting-only whitespace collapsed."""

    return " ".join(text.split())


def test_publish_requires_exact_current_protected_develop_tip() -> None:
    """Publishing must fail closed when a dispatch or tag is not the live develop tip."""

    workflow = _read(".github/workflows/publish-pypi.yml")

    assert "git fetch --no-tags origin develop" in workflow
    assert 'protected_sha="$(git rev-parse origin/develop)"' in workflow
    assert 'if [ "$GITHUB_SHA" != "$protected_sha" ]; then' in workflow
    assert 'refs/heads/develop' in workflow
    assert 'refs/tags/v${project_version}' in workflow
    assert 'case "$GITHUB_EVENT_NAME" in' in workflow
    assert 'workflow_dispatch)' in workflow
    assert 'push)' in workflow


def test_publish_smoke_tests_the_built_wheel_outside_source_tree() -> None:
    """Release evidence must prove the actual wheel imports and exposes packaged assets."""

    workflow = _read(".github/workflows/publish-pypi.yml")

    assert 'python -m venv "$RUNNER_TEMP/appguardrail-release-smoke"' in workflow
    assert 'pip install --disable-pip-version-check --no-deps dist/*.whl' in workflow
    assert 'cd "$RUNNER_TEMP"' in workflow
    assert '"$smoke_env/bin/appguardrail" --version' in workflow
    assert "scanner.rules" in workflow
    assert "scanner/dashboard" in workflow


def test_release_runbook_explains_fail_closed_source_and_artifact_boundary() -> None:
    """Operators must understand why arbitrary branches cannot invoke the publisher."""

    runbook = _squash_whitespace(_read("docs/release-automation.md"))

    assert "Protected-source release gate" in runbook
    assert "exact current `develop` tip" in runbook
    assert "manual dispatch from another branch" in runbook
    assert "tag/version mismatch" in runbook
    assert "fresh virtual environment" in runbook
    assert "GitHub Docs. (2026)." in runbook
    assert "Python Packaging Authority. (2026)." in runbook
    assert "## References (APA 7th)" in runbook
