"""Tests for the `appguardrail rules` listing command."""

import json
import subprocess
import sys
from pathlib import Path

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
