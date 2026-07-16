"""Tests for safe auto-fixes (appguardrail_core.autofix) and `appguardrail fix`."""

import pytest

from appguardrail_core.autofix import apply_safe_fixes, fixable_extensions
from scanner.cli.appguardrail import cmd_fix


class _Args:
    def __init__(self, path, apply=False):
        self.path = path
        self.apply = apply


def test_noopener_only_fixes_external_rel_less_blank():
    src = (
        '<a href="https://x.com" target="_blank">x</a>\n'
        '<a href="/local" target="_blank">local</a>\n'
        '<a href="https://y.com" target="_blank" rel="noopener">y</a>'
    )
    out, n = apply_safe_fixes(src, ".html")
    assert n == 1  # only the external, rel-less link
    assert 'rel="noopener noreferrer"' in out
    assert '<a href="/local"' in out  # local untouched
    assert out.count("rel=") == 2  # existing rel preserved


def test_idempotent_and_extension_scoped():
    src = '<a href="https://x.com" target="_blank">x</a>'
    out, n = apply_safe_fixes(src, ".html")
    assert n == 1
    _, again = apply_safe_fixes(out, ".html")
    assert again == 0  # nothing left to fix
    _, other = apply_safe_fixes(src, ".py")
    assert other == 0  # non-html extension is a no-op
    assert ".html" in fixable_extensions()


def test_rel_substrings_are_not_treated_as_safe_tokens():
    unsafe_values = ("notnoopener", "noopenerx", "noreferrerfoo", "foo noopenerbar baz")
    for value in unsafe_values:
        source = f'<a href="https://example.com" target="_blank" rel="{value}">x</a>'
        fixed, count = apply_safe_fixes(source, ".html")
        assert count == 1
        assert f'rel="{value} noopener noreferrer"' in fixed


def test_exact_safe_rel_token_remains_unchanged():
    source = (
        '<a href="https://example.com" target="_blank" rel="nofollow noopener">x</a>'
    )
    fixed, count = apply_safe_fixes(source, ".html")
    assert count == 0
    assert fixed == source


@pytest.mark.parametrize("value", (r"\999", r"\1"))
def test_rel_backslashes_are_literal_not_regex_replacements(value):
    source = f'<a href="https://example.com" target="_blank" rel="{value}">x</a>'
    fixed, count = apply_safe_fixes(source, ".html")
    assert count == 1
    assert f'rel="{value} noopener noreferrer"' in fixed


def test_cmd_fix_dry_run_does_not_write(tmp_path, capsys):
    f = tmp_path / "page.html"
    f.write_text('<a href="https://x.com" target="_blank">x</a>')
    assert cmd_fix(_Args(str(tmp_path), apply=False)) == 0
    assert "noopener" not in f.read_text()  # dry-run leaves file untouched
    assert "--apply" in capsys.readouterr().out


def test_cmd_fix_apply_writes(tmp_path, capsys):
    f = tmp_path / "page.html"
    f.write_text('<a href="https://x.com" target="_blank">x</a>')
    assert cmd_fix(_Args(str(tmp_path), apply=True)) == 0
    assert 'rel="noopener noreferrer"' in f.read_text()
    assert "Applied 1 safe fix" in capsys.readouterr().out


def test_cmd_fix_nothing_to_do(tmp_path, capsys):
    (tmp_path / "clean.html").write_text('<a href="/local">ok</a>')
    assert cmd_fix(_Args(str(tmp_path))) == 0
    assert "No safe auto-fixes" in capsys.readouterr().out
