"""Scanner regression for protected-source PyPI publishing (#967)."""

from pathlib import Path

import pytest

from scanner.cli.appguardrail import _scan_file

FIXTURES = Path(__file__).parent / "fixtures" / "release_source"
RULE = "github-actions-pypi-unbound-release-source"


def _scan(tmp_path, text):
    """Exercise packaged rules through the normal scanner file boundary."""
    path = tmp_path / ".github" / "workflows" / "release.yml"
    path.parent.mkdir(parents=True)
    path.write_text(text, encoding="utf-8")
    return [finding for finding in _scan_file(path, tmp_path) if finding["rule_id"] == RULE]


def _oracle(name):
    """Read the immutable source evidence copied byte-for-byte from Git."""
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_protected_source_unbound_pypi_release_is_reported(tmp_path):
    """Manual/tag source reaches a PyPI publisher without source validation."""
    findings = _scan(tmp_path, _oracle("protected-vulnerable.yml"))
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    expected_line = _oracle("protected-vulnerable.yml").splitlines().index(
        "        uses: pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33 # release/v1"
    ) + 1
    assert findings[0]["line"] == expected_line


def test_reviewed_protected_source_gate_is_not_reported(tmp_path):
    """The reviewed gate dominates the same source build feeding publication."""
    assert _scan(tmp_path, _oracle("pr967-fixed.yml")) == []


@pytest.mark.parametrize("mutation", [
    "echo-only", "comment-only", "late", "conditional", "continue-on-error",
    "sibling", "missing-exit", "ignored-fetch", "mutable-checkout",
    "late-continue-on-error", "job-continue-on-error", "second-checkout",
])
def test_non_dominating_or_non_enforcing_gate_cannot_donate_proof(tmp_path, mutation):
    """Near-miss evidence must not conceal an unbound release source."""
    text = _oracle("pr967-fixed.yml")
    start = text.index("      - name: Verify protected release source")
    end = text.index("      - name: Install build tooling", start)
    gate = text[start:end]
    if mutation == "echo-only":
        gate = '      - run: echo \'git fetch --no-tags origin develop; protected_sha; GITHUB_SHA; exit 1\'\n'
    elif mutation == "comment-only":
        gate = "\n".join("# " + line for line in gate.splitlines()) + "\n"
    elif mutation == "late":
        text = text.replace(gate, "")
        text = text.replace("      - name: Check package distributions", gate + "      - name: Check package distributions")
        assert _scan(tmp_path, text)
        return
    elif mutation == "conditional":
        gate = gate.replace("        run: |", "        if: github.event_name == 'push'\n        run: |")
    elif mutation == "continue-on-error":
        gate = gate.replace("        run: |", "        continue-on-error: true\n        run: |")
    elif mutation == "sibling":
        text = text.replace(gate, "")
        text += "\n  unrelated:\n    runs-on: ubuntu-latest\n    steps:\n" + gate
        assert _scan(tmp_path, text)
        return
    elif mutation == "missing-exit":
        gate = gate.replace("            exit 1", "            echo rejected")
    elif mutation == "ignored-fetch":
        gate = gate.replace("git fetch --no-tags origin develop", "git fetch --no-tags origin develop || true")
    elif mutation == "mutable-checkout":
        text = text.replace("          fetch-depth: 0", "          fetch-depth: 0\n          ref: mutable-branch")
        assert _scan(tmp_path, text)
        return
    elif mutation == "late-continue-on-error":
        gate += "        continue-on-error: true\n"
    elif mutation == "job-continue-on-error":
        text = text.replace("  build:\n", "  build:\n    continue-on-error: true\n")
        assert _scan(tmp_path, text)
        return
    elif mutation == "second-checkout":
        text = text.replace("      - name: Install build tooling", "      - uses: actions/checkout@abc\n      - name: Install build tooling")
        assert _scan(tmp_path, text)
        return
    assert _scan(tmp_path, text.replace(text[start:end], gate))


@pytest.mark.parametrize("mutation", [
    "no-publisher", "action-in-run", "push-branches-only", "unrelated-permission",
    "no-trigger", "no-jobs",
])
def test_non_release_source_shapes_are_not_reported(tmp_path, mutation):
    """Unrelated authority and publisher-looking text are not PyPI release jobs."""
    text = _oracle("protected-vulnerable.yml")
    if mutation == "no-publisher":
        text = text[:text.index("  publish:")]
    elif mutation == "action-in-run":
        text = text.replace("uses: pypa/gh-action-pypi-publish@", "run: echo pypa/gh-action-pypi-publish@")
    elif mutation == "push-branches-only":
        text = text.replace("  workflow_dispatch:\n", "").replace("    tags:", "    branches:")
    elif mutation == "unrelated-permission":
        text = text[:text.index("  publish:")] + "\n  unrelated:\n    permissions:\n      id-token: write\n    steps:\n      - run: echo pypa/gh-action-pypi-publish@main\n"
    elif mutation == "no-trigger":
        text = text.replace("on:", "events:", 1)
    else:
        text = text.replace("jobs:", "tasks:", 1)
    assert _scan(tmp_path, text) == []


@pytest.mark.parametrize("trigger", [
    "on: workflow_dispatch",
    "'on':\n  push:\n    tags:\n      - v*",
])
def test_inline_build_and_dependency_cycle_do_not_hide_unbound_source(tmp_path, trigger):
    """Scalar/list needs are followed once even with missing or cyclic jobs."""
    text = trigger + """
jobs:
  build:
    needs: [missing, publish]
    steps:
      - uses: actions/checkout@abc
      - run: python -m build
  publish:
    needs: [build]
    steps:
      - uses: pypa/gh-action-pypi-publish@abc
"""
    assert len(_scan(tmp_path, text)) == 1


def test_same_job_inline_build_and_publication_remains_in_scope(tmp_path):
    """Publication does not need an artifact handoff to need source policy."""
    text = """on: workflow_dispatch
jobs:
  release:
    steps:
      - run: python -m build
      - uses: pypa/gh-action-pypi-publish@abc
"""
    assert len(_scan(tmp_path, text)) == 1


def test_comment_only_manual_trigger_cannot_expand_branch_push_scope(tmp_path):
    """An inert workflow_dispatch comment is not an executable event."""
    text = _oracle("protected-vulnerable.yml")
    text = text.replace("  workflow_dispatch:", "  # workflow_dispatch:")
    text = text.replace("    tags:", "    branches:")
    assert _scan(tmp_path, text) == []


@pytest.mark.parametrize("key, value", [
    ("repository", "other/project"),
    ('"repository"', "other/project"),
    ("'repository'", "other/project"),
    ('"ref"', "mutable-branch"),
    ("'ref'", "mutable-branch"),
])
def test_other_repository_checkout_cannot_donate_protected_source_proof(tmp_path, key, value):
    """GITHUB_SHA from this repository does not bind another repository source."""
    text = _oracle("pr967-fixed.yml").replace(
        "          fetch-depth: 0",
        f"          fetch-depth: 0\n          {key}: {value}",
    )
    assert len(_scan(tmp_path, text)) == 1


@pytest.mark.parametrize("quote", ['"', "'"])
@pytest.mark.parametrize("boundary", ["if", "continue-on-error", "shell", "job-error", "second-checkout"])
def test_quoted_proof_boundary_keys_cannot_donate_enforcement(tmp_path, quote, boundary):
    """Quoting a YAML key cannot turn a non-enforcing gate into proof."""
    text = _oracle("pr967-fixed.yml")
    if boundary == "job-error":
        text = text.replace("  build:\n", f"  build:\n    {quote}continue-on-error{quote}: true\n")
    elif boundary == "second-checkout":
        text = text.replace(
            "      - name: Install build tooling",
            f"      - {quote}uses{quote}: actions/checkout@abc\n      - name: Install build tooling",
        )
    else:
        value = {"if": "false", "continue-on-error": "true", "shell": "bash {0} || true"}[boundary]
        text = text.replace(
            "      - name: Verify protected release source\n        run: |",
            f"      - name: Verify protected release source\n        {quote}{boundary}{quote}: {value}\n        run: |",
        )
    assert len(_scan(tmp_path, text)) == 1


@pytest.mark.parametrize("quote", ['"', "'"])
def test_quoted_publisher_key_cannot_hide_release_sink(tmp_path, quote):
    """A quoted uses key still invokes the PyPI publisher action."""
    text = _oracle("protected-vulnerable.yml").replace(
        "uses: pypa/gh-action-pypi-publish@",
        f"{quote}uses{quote}: pypa/gh-action-pypi-publish@",
    )
    assert len(_scan(tmp_path, text)) == 1


@pytest.mark.parametrize("quote", ['"', "'"])
def test_quoted_tag_trigger_still_reaches_unbound_publication(tmp_path, quote):
    """Quoted block push/tags keys preserve the tag release entry point."""
    text = _oracle("protected-vulnerable.yml").replace("  workflow_dispatch:\n", "")
    text = text.replace("  push:", f"  {quote}push{quote}:")
    text = text.replace("    tags:", f"    {quote}tags{quote}:")
    assert len(_scan(tmp_path, text)) == 1


@pytest.mark.parametrize("quote", ["", '"', "'"])
@pytest.mark.parametrize("boundary", ["if", "continue-on-error", "shell"])
def test_first_key_gate_metadata_cannot_donate_enforcement(tmp_path, quote, boundary):
    """Step-first metadata has the same effect as subsequent mapping fields."""
    value = {"if": "false", "continue-on-error": "true", "shell": "bash {0} || true"}[boundary]
    text = _oracle("pr967-fixed.yml").replace(
        "      - name: Verify protected release source",
        f"      - {quote}{boundary}{quote}: {value}",
    )
    assert len(_scan(tmp_path, text)) == 1


@pytest.mark.parametrize("quote", ["", '"', "'"])
@pytest.mark.parametrize("key, value", [("repository", "other/project"), ("ref", "mutable-branch")])
def test_inline_checkout_override_cannot_donate_protected_source(tmp_path, quote, key, value):
    """Flow-style checkout source overrides are not default source checkout."""
    text = _oracle("pr967-fixed.yml").replace(
        "        with:\n          fetch-depth: 0",
        f"        with: {{{quote}{key}{quote}: {value}, fetch-depth: 0}}",
        1,
    )
    assert len(_scan(tmp_path, text)) == 1


def test_mixed_case_publisher_cannot_be_filtered_out_before_matcher(tmp_path):
    """The scanner admission filter must preserve case-insensitive action names."""
    text = _oracle("protected-vulnerable.yml").replace(
        "pypa/gh-action-pypi-publish@", "PyPA/Gh-Action-PyPI-Publish@"
    )
    assert len(_scan(tmp_path, text)) == 1


@pytest.mark.parametrize("quote", ["", '"', "'"])
@pytest.mark.parametrize("boundary", [
    "publisher", "on", "workflow_dispatch", "push-tags", "if",
    "continue-on-error", "shell", "job-error", "ref", "repository", "with",
])
def test_supported_yaml_key_spacing_preserves_policy_semantics(tmp_path, quote, boundary):
    """Whitespace before a supported mapping key colon cannot bypass policy."""
    unsafe = boundary in {"publisher", "on", "workflow_dispatch", "push-tags"}
    text = _oracle("protected-vulnerable.yml" if unsafe else "pr967-fixed.yml")
    if boundary == "publisher":
        text = text.replace("uses: pypa/", f"{quote}uses{quote} : pypa/")
    elif boundary == "on":
        text = text.replace("on:", f"{quote}on{quote} :", 1)
    elif boundary == "workflow_dispatch":
        text = text.replace("  workflow_dispatch:", f"  {quote}workflow_dispatch{quote} :")
        text = text.replace("    tags:", "    branches:")
    elif boundary == "push-tags":
        text = text.replace("  workflow_dispatch:\n", "")
        text = text.replace("  push:", f"  {quote}push{quote} :")
        text = text.replace("    tags:", f"    {quote}tags{quote} :")
    elif boundary == "job-error":
        text = text.replace("  build:\n", f"  build:\n    {quote}continue-on-error{quote} : true\n")
    elif boundary in {"ref", "repository"}:
        value = "mutable-branch" if boundary == "ref" else "other/project"
        text = text.replace("          fetch-depth: 0", f"          {quote}{boundary}{quote} : {value}\n          fetch-depth: 0", 1)
    elif boundary == "with":
        text = text.replace(
            "        with:\n          fetch-depth: 0",
            f"        {quote}with{quote} : {{{quote}repository{quote} : other/project}}",
            1,
        )
    else:
        value = {"if": "false", "continue-on-error": "true", "shell": "bash {0} || true"}[boundary]
        text = text.replace(
            "      - name: Verify protected release source",
            f"      - {quote}{boundary}{quote} : {value}",
        )
    assert len(_scan(tmp_path, text)) == 1
