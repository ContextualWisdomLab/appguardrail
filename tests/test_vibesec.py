import pytest
from pathlib import Path
from scanner.cli.vibesec import _scan_file
import os
import tempfile
import re
from unittest.mock import patch

MOCK_RULES = [
    {
        "id": "mock-secret",
        "pattern": re.compile(r'MOCK_SECRET_KEY'),
        "severity": "CRITICAL",
        "message": "Found mock secret",
        "extensions": None,
    },
    {
        "id": "mock-todo",
        "pattern": re.compile(r'TODO: fix auth'),
        "severity": "HIGH",
        "message": "Found auth todo",
        "extensions": None,
    },
    {
        "id": "mock-rules-ext",
        "pattern": re.compile(r'allow all'),
        "severity": "CRITICAL",
        "message": "Allows all",
        "extensions": [".rules"],
    }
]

@patch('scanner.cli.vibesec.SCAN_RULES', MOCK_RULES)
def test_scan_file_no_findings():
    with tempfile.TemporaryDirectory() as tmpdir:
        base_path = Path(tmpdir)
        test_file = base_path / "safe.py"
        test_file.write_text("print('hello')\n")

        findings = _scan_file(test_file, base_path)
        assert len(findings) == 0

@patch('scanner.cli.vibesec.SCAN_RULES', MOCK_RULES)
def test_scan_file_with_findings():
    with tempfile.TemporaryDirectory() as tmpdir:
        base_path = Path(tmpdir)
        test_file = base_path / "unsafe.ts"
        test_file.write_text("const key = MOCK_SECRET_KEY;\n")

        findings = _scan_file(test_file, base_path)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "mock-secret"

@patch('scanner.cli.vibesec.SCAN_RULES', MOCK_RULES)
def test_scan_file_with_multiple_findings():
    with tempfile.TemporaryDirectory() as tmpdir:
        base_path = Path(tmpdir)
        test_file = base_path / "unsafe_multiple.js"
        content = """
const key = MOCK_SECRET_KEY;
// TODO: fix auth checks here
        """
        test_file.write_text(content)

        findings = _scan_file(test_file, base_path)
        assert len(findings) == 2
        rule_ids = [f["rule_id"] for f in findings]
        assert "mock-secret" in rule_ids
        assert "mock-todo" in rule_ids

def test_scan_file_unreadable():
    with tempfile.TemporaryDirectory() as tmpdir:
        base_path = Path(tmpdir)
        test_file = base_path / "unreadable.ts"
        test_file.write_text("MOCK_SECRET_KEY\n")

        # Mock read_text to raise PermissionError, making it cross-platform
        with patch.object(Path, 'read_text', side_effect=PermissionError("Permission denied")):
            findings = _scan_file(test_file, base_path)
            assert findings == []

@patch('scanner.cli.vibesec.SCAN_RULES', MOCK_RULES)
def test_scan_file_extensions_filter():
    with tempfile.TemporaryDirectory() as tmpdir:
        base_path = Path(tmpdir)
        test_file = base_path / "rules.js" # extension mismatch
        test_file.write_text("allow all\n")

        findings = _scan_file(test_file, base_path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "mock-rules-ext" not in rule_ids

        test_file_rules = base_path / "firestore.rules"
        test_file_rules.write_text("allow all\n")

        findings = _scan_file(test_file_rules, base_path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "mock-rules-ext" in rule_ids
