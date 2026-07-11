"""Tests for the `appguardrail rules` listing command."""

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from scanner.cli import appguardrail as cli

REPO = Path(__file__).resolve().parents[1]
CLI = [sys.executable, str(REPO / "scanner" / "cli" / "appguardrail.py")]


def _run(*args):
    return subprocess.run(CLI + list(args), capture_output=True, text=True)


def test_rules_human_output():
    r = _run("rules")
    assert r.returncode == 0
    assert "detection rules loaded" in r.stdout
    assert "CRITICAL" in r.stdout
    # every listed line carries a scope
    assert "(all files)" in r.stdout or "(." in r.stdout


def test_rules_json_output():
    r = _run("rules", "--json")
    assert r.returncode == 0
    payload = json.loads(r.stdout)
    assert payload["schema"] == "appguardrail.rules.v1"
    assert payload["count"] == len(payload["rules"]) > 50
    sample = payload["rules"][0]
    assert set(sample) == {"id", "severity", "extensions", "message"}
    # sorted: CRITICAL first
    assert payload["rules"][0]["severity"] == "CRITICAL"


def test_cmd_rules_human_output(capsys):
    assert cli.cmd_rules(SimpleNamespace(json=False)) == 0
    out = capsys.readouterr().out
    assert "detection rules loaded" in out
    assert "CRITICAL" in out
    assert "(all files)" in out or "(." in out


def test_cmd_rules_json_output(capsys):
    assert cli.cmd_rules(SimpleNamespace(json=True)) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "appguardrail.rules.v1"
    assert payload["count"] == len(payload["rules"]) > 50
    assert payload["rules"][0]["severity"] == "CRITICAL"
