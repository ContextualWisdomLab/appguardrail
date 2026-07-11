"""Tests for the findings diff report (appguardrail_core.diffreport)."""

import json
from types import SimpleNamespace

from appguardrail_core.diffreport import diff_findings, load_findings, render_diff_report
from scanner.cli.appguardrail import cmd_diff_report

OLD = [
    {"severity": "CRITICAL", "rule_id": "secret", "file": "a.ts", "line": 3,
     "message": "hardcoded key", "context": "app-code"},
    {"severity": "HIGH", "rule_id": "rls", "file": "db.sql", "line": 9,
     "message": "RLS off", "context": "app-code"},
]
NEW = [
    # same finding, moved lines -> persisting, not fixed+new
    {"severity": "HIGH", "rule_id": "rls", "file": "db.sql", "line": 14,
     "message": "RLS off", "context": "app-code"},
    {"severity": "HIGH", "rule_id": "cors", "file": "api.ts", "line": 2,
     "message": "wildcard origin", "context": "app-code"},
]


def test_diff_buckets_line_independent():
    d = diff_findings(OLD, NEW)
    assert [f["rule_id"] for f in d["fixed"]] == ["secret"]
    assert [f["rule_id"] for f in d["new"]] == ["cors"]
    assert [f["rule_id"] for f in d["persisting"]] == ["rls"]


def test_render_regression_verdict():
    md = render_diff_report(OLD, NEW)
    assert md.startswith("# ")
    assert "회귀" in md  # new blocking present
    assert "`cors`" in md and "`secret`" in md and "`rls`" in md


def test_render_improved_verdict():
    md = render_diff_report(OLD, [])
    assert "개선" in md
    md2 = render_diff_report(OLD, OLD)
    assert "변화 없음" in md2


def test_progress_verdict():
    # one blocking fixed, one persisting, none new
    md = render_diff_report(OLD, [OLD[1]])
    assert "진행 중" in md


def test_load_findings_shapes(tmp_path):
    env = tmp_path / "env.json"
    env.write_text(json.dumps({"schema": "x", "findings": OLD}), encoding="utf-8")
    assert load_findings(str(env)) == OLD
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps(OLD), encoding="utf-8")
    assert load_findings(str(bare)) == OLD


def test_cmd_diff_report_stdout(tmp_path, capsys):
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    old_path.write_text(json.dumps(OLD), encoding="utf-8")
    new_path.write_text(json.dumps(NEW), encoding="utf-8")

    rc = cmd_diff_report(
        SimpleNamespace(old=str(old_path), new=str(new_path), out=None)
    )

    assert rc == 0
    out = capsys.readouterr().out
    assert "회귀" in out
    assert "`cors`" in out


def test_cmd_diff_report_writes_file(tmp_path, capsys):
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    out_path = tmp_path / "report.md"
    old_path.write_text(json.dumps(OLD), encoding="utf-8")
    new_path.write_text(json.dumps([]), encoding="utf-8")

    rc = cmd_diff_report(
        SimpleNamespace(old=str(old_path), new=str(new_path), out=str(out_path))
    )

    assert rc == 0
    assert "Diff report written" in capsys.readouterr().out
    assert "개선" in out_path.read_text(encoding="utf-8")
