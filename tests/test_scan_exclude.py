"""Tests for `appguardrail scan --exclude <glob>` path filtering."""

import json
from types import SimpleNamespace

from scanner.cli.appguardrail import cmd_scan

_SECRET = 'const apiKey = "api_key=AbCdEf0123456789ABCDEF0123456789";\n'


def _args(path, out, exclude=None):
    return SimpleNamespace(
        path=str(path), trivy=False, external="off", bandit=False, ruff=False,
        semgrep=False, semgrep_config=None, zap_baseline=None, codegraph=False,
        findings_json=str(out), sarif=None, exclude=exclude,
    )


def _count(out):
    return len(json.loads(out.read_text())["findings"])


def _files(out):
    return {f["file"] for f in json.loads(out.read_text())["findings"]}


def test_no_exclude_scans_all(tmp_path):
    (tmp_path / "src").mkdir(); (tmp_path / "vendor").mkdir()
    (tmp_path / "src" / "app.js").write_text(_SECRET)
    (tmp_path / "vendor" / "lib.js").write_text(_SECRET)
    out = tmp_path / "f.json"
    cmd_scan(_args(tmp_path, out))
    assert _count(out) == 2


def test_exclude_by_path_glob(tmp_path):
    (tmp_path / "src").mkdir(); (tmp_path / "vendor").mkdir()
    (tmp_path / "src" / "app.js").write_text(_SECRET)
    (tmp_path / "vendor" / "lib.js").write_text(_SECRET)
    out = tmp_path / "f.json"
    cmd_scan(_args(tmp_path, out, exclude=["vendor/*"]))
    files = _files(out)
    assert len(files) == 1 and not any("vendor" in f for f in files)


def test_exclude_by_filename_glob(tmp_path):
    (tmp_path / "app.js").write_text(_SECRET)
    out = tmp_path / "f.json"
    cmd_scan(_args(tmp_path, out, exclude=["*.js"]))
    assert _count(out) == 0


def test_multiple_excludes(tmp_path):
    (tmp_path / "a.js").write_text(_SECRET)
    (tmp_path / "b.ts").write_text(_SECRET)
    (tmp_path / "c.py").write_text('api_key = "AKIAIOSFODNN7EXAMPLE"\n')
    out = tmp_path / "f.json"
    cmd_scan(_args(tmp_path, out, exclude=["*.js", "*.ts"]))
    assert not any(f.endswith((".js", ".ts")) for f in _files(out))
