import os
import json
import subprocess
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock

from scanner.cli.appguardrail import (
    cmd_scan, _run_trivy_fs, _finding_context, _finding_category, _trivy_target,
    _scan_file, _trivy_severity, _trivy_line, _trivy_findings, _build_finding,
    _confidence, _is_deploy_blocking
)
from tests.test_appguardrail_coverage import ScanArgs

def test_run_trivy_fs_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    def mock_subprocess_run(*args, **kwargs):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Simulated error\n"
        return mock_result

    with patch("subprocess.run", side_effect=mock_subprocess_run):
        with patch("shutil.which", return_value="trivy"):
            with pytest.raises(RuntimeError, match="Trivy scan failed: Simulated error"):
                _run_trivy_fs(tmp_path)

def test_run_trivy_fs_invalid_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    def mock_subprocess_run(*args, **kwargs):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "invalid json"
        return mock_result

    with patch("subprocess.run", side_effect=mock_subprocess_run):
        with patch("shutil.which", return_value="trivy"):
            with pytest.raises(RuntimeError, match="Trivy returned invalid JSON"):
                _run_trivy_fs(tmp_path)

def test_finding_context_examples():
    assert _finding_context("examples/test.py") == "example"

def test_finding_context_tests():
    assert _finding_context("tests/test.py") == "test"

def test_finding_context_docs():
    assert _finding_context("docs/test.py") == "doc"

def test_finding_context_scanner_fixture():
    assert _finding_context("scanner/rules/test.yml") == "scanner-fixture"

def test_finding_context_scanner_fixture_appguardrail():
    assert _finding_context("scanner/cli/appguardrail.py", '"id": "test"') == "scanner-fixture"

def test_finding_category_cve():
    assert _finding_category("cve-1234") == "dependency"

def test_finding_category_payment():
    assert _finding_category("stripe-test") == "payment"

def test_finding_category_storage():
    assert _finding_category("firebase-test") == "storage"

def test_finding_category_authz():
    assert _finding_category("auth-test") == "authz"

def test_finding_category_injection():
    assert _finding_category("eval-test") == "injection"

def test_trivy_target_empty(tmp_path):
    assert _trivy_target("", tmp_path) == str(tmp_path)

def test_trivy_target_absolute_valueerror(tmp_path):
    # base is a non-existent file (not a dir), so root = base.parent = tmp_path
    base = tmp_path / "base_file.txt"
    target = str(tmp_path / "other" / "path.txt")
    assert _trivy_target(target, base) == "other/path.txt"

def test_scan_file_empty_file(tmp_path):
    empty_file = tmp_path / "empty.ts"
    empty_file.touch()
    assert _scan_file(empty_file, tmp_path) == []

def test_scan_file_no_newline_after_match(tmp_path):
    file_content = "const password = 'verysecretpassword';"
    test_file = tmp_path / "unsafe.ts"
    test_file.write_text(file_content)

    import re
    MOCK_RULES = [{
        "id": "test-rule",
        "severity": "CRITICAL",
        "message": "Test",
        "extensions": [".ts"],
        "pattern": re.compile(r"password")
    }]

    with patch("scanner.cli.appguardrail.SCAN_RULES", MOCK_RULES):
        findings = _scan_file(test_file, tmp_path)
        assert len(findings) > 0
        assert findings[0]["snippet"].startswith("const password")

def test_cmd_scan_trivy_error_handled(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    def mock_run_trivy(*args):
        raise RuntimeError("Mock trivy failure")

    with patch("scanner.cli.appguardrail._run_trivy_fs", side_effect=mock_run_trivy):
        class TrivyArgs(ScanArgs):
            def __init__(self, path):
                super().__init__(path)
                self.trivy = True

        assert cmd_scan(TrivyArgs(tmp_path)) == 1
        err = capsys.readouterr().err
        assert "Error: Mock trivy failure" in err
        assert "💡 Hint: Ensure Trivy is installed and running correctly, or run without --trivy." in err


def test_cmd_scan_codegraph_error_handled(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    def mock_run_codegraph(*args):
        raise RuntimeError("Mock CodeGraph failure")

    with patch(
        "scanner.cli.appguardrail._run_codegraph_index",
        side_effect=mock_run_codegraph,
    ):
        class CodeGraphArgs(ScanArgs):
            def __init__(self, path):
                super().__init__(path)
                self.codegraph = True

        assert cmd_scan(CodeGraphArgs(tmp_path)) == 1
        err = capsys.readouterr().err
        assert "Error: Mock CodeGraph failure" in err
        assert "Install the CodeGraph CLI or run without --codegraph." in err


def test_trivy_severity():
    assert _trivy_severity("CRITICAL") == "CRITICAL"
    assert _trivy_severity("HIGH") == "HIGH"
    assert _trivy_severity("MEDIUM") == "WARNING"
    assert _trivy_severity("LOW") == "INFO"
    assert _trivy_severity("UNKNOWN") == "INFO"

def test_trivy_line():
    assert _trivy_line({"StartLine": 10}) == 10
    assert _trivy_line({"CauseMetadata": {"StartLine": 20}}) == 20
    assert _trivy_line({}) == 1

def test_trivy_findings_parsing(tmp_path):
    report = {
        "Results": [
            {
                "Target": "test.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-1234",
                        "Severity": "CRITICAL",
                        "Title": "Test Vuln",
                        "PkgName": "test-pkg",
                        "InstalledVersion": "1.0",
                        "FixedVersion": "1.1"
                    }
                ],
                "Misconfigurations": [
                    {
                        "ID": "AVD-AWS-0001",
                        "Severity": "HIGH",
                        "Title": "S3 bucket exposed",
                        "Message": "Bucket is public",
                        "CauseMetadata": {"StartLine": 15}
                    }
                ],
                "Secrets": [
                    {
                        "RuleID": "aws-access-key",
                        "Severity": "CRITICAL",
                        "Title": "AWS Access Key",
                        "StartLine": 5
                    }
                ]
            }
        ]
    }
    findings = _trivy_findings(report, tmp_path)
    assert len(findings) == 3
    assert findings[0]["rule_id"] == "trivy:CVE-2023-1234"
    assert findings[1]["rule_id"] == "trivy:AVD-AWS-0001"
    assert findings[2]["rule_id"] == "trivy:aws-access-key"

def test_confidence():
    assert _confidence("trivy:cve") == "high"
    assert _confidence("hardcoded-password") == "high"
    assert _confidence("todo-test") == "medium"
    assert _confidence("random") == "high"

def test_is_deploy_blocking():
    assert _is_deploy_blocking({"severity": "CRITICAL", "context": "app-code"}) == True
    assert _is_deploy_blocking({"severity": "HIGH", "context": "app-code"}) == True
    assert _is_deploy_blocking({"severity": "MEDIUM", "context": "app-code"}) == False
    assert _is_deploy_blocking({"severity": "CRITICAL", "context": "test"}) == False


def test_trivy_target_value_error():
    base = Path("/opt/project")
    # path is absolute and definitely not relative to base
    assert _trivy_target("/etc/passwd", base) == "/etc/passwd"
