"""Tests for GitHub Actions native output (appguardrail_core.github_actions)."""

import os

from appguardrail_core import github_actions as ga

FINDINGS = [
    {"severity": "CRITICAL", "rule_id": "secret", "file": "a,b.ts", "line": 3,
     "message": "hardcoded <key>\nrotate", "context": "app-code"},
    {"severity": "HIGH", "rule_id": "rls", "file": "db.sql", "line": 7,
     "message": "RLS off", "context": "app-code"},
    {"severity": "INFO", "rule_id": "note", "file": "README.md", "line": 1,
     "message": "fyi", "context": "doc"},
]


def test_in_actions_env(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert ga.in_actions() is True
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    assert ga.in_actions() is False
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    assert ga.in_actions() is False


def test_annotation_levels_and_escaping():
    lines = ga.annotation_lines(FINDINGS)
    assert lines[0].startswith("::error ")     # CRITICAL app-code -> blocking
    assert lines[1].startswith("::error ")     # HIGH app-code -> blocking
    assert lines[2].startswith("::warning ")   # INFO/doc -> not blocking
    # comma in filename escaped in the property, newline escaped in message
    assert "file=a%2Cb.ts" in lines[0]
    assert "%0A" in lines[0]
    assert "\n" not in lines[0]  # single-line command


def test_annotation_respects_custom_blocking_fn():
    # Treat nothing as blocking -> all warnings.
    lines = ga.annotation_lines(FINDINGS, is_blocking=lambda f: False)
    assert all(l.startswith("::warning ") for l in lines)


def test_step_summary_markdown():
    md = ga.step_summary_md(FINDINGS, files_scanned=4)
    assert md.startswith("## ")
    assert "deploy-blocking" in md
    assert "CRITICAL" in md and "HIGH" in md
    assert "`secret`" in md  # rule listed
    # empty case
    assert ga.step_summary_md([], 4).rstrip().endswith("✅")


def test_emit_writes_summary_file(tmp_path, monkeypatch, capsys):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    ga.emit(FINDINGS, files_scanned=4)
    out = capsys.readouterr().out
    assert "::error " in out and "::warning " in out
    assert summary.read_text(encoding="utf-8").startswith("## ")


def test_emit_survives_bad_summary_path(monkeypatch, capsys):
    # An unwritable summary path must not raise.
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", "/nonexistent-dir/x/summary.md")
    ga.emit(FINDINGS, files_scanned=4)  # should not raise
    assert "::error " in capsys.readouterr().out
