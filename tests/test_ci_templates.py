"""Smoke tests for the ci-templates/ pipeline configs.

These are plain YAML/docs, so we avoid a YAML dependency (PyYAML may be absent)
and instead assert that each template exists, is non-empty, and invokes the
real AppGuardrail scan entry point.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CI_TEMPLATES = REPO_ROOT / "ci-templates"

# The real scan invocation every template must contain. If the CLI module path
# or subcommand name changes, these templates (and this assertion) must too.
SCAN_INVOCATION = "scanner.cli.appguardrail scan"

TEMPLATE_FILES = ["gitlab-ci.yml", "circleci-config.yml"]


def test_ci_templates_dir_exists():
    assert CI_TEMPLATES.is_dir(), f"missing ci-templates/ at {CI_TEMPLATES}"


def test_templates_exist_and_invoke_scanner():
    for name in TEMPLATE_FILES:
        path = CI_TEMPLATES / name
        assert path.is_file(), f"missing template: {path}"
        text = path.read_text(encoding="utf-8")
        assert text.strip(), f"template is empty: {path}"
        assert SCAN_INVOCATION in text, (
            f"{path} does not invoke '{SCAN_INVOCATION}'"
        )


def test_readme_exists_and_non_empty():
    readme = CI_TEMPLATES / "README.md"
    assert readme.is_file(), f"missing {readme}"
    assert readme.read_text(encoding="utf-8").strip(), "ci-templates README is empty"
