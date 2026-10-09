"""Execute the shipped dashboard filter/sort hot path as a regression contract."""

import json
import re
import subprocess
from pathlib import Path

from scanner.cli.appguardrail import dashboard_index_path


_REPO_ROOT = Path(__file__).resolve().parents[1]
_TESTS_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "tests.yml"


def _run_shipped_filter(findings, *, severity="", query=""):
    """Execute the filter/sort block extracted from the shipped dashboard source."""
    html = dashboard_index_path().read_text(encoding="utf-8")
    order = re.search(
        r"const SEV_ORDER = \[[^\n]+\];\n"
        r"const SEV_ORDER_MAP = Object\.fromEntries\([^\n]+\);",
        html,
    )
    hot_path = re.search(
        r"  const filtered = \[\];\n(?P<body>.*?)"
        r"  filtered\.sort\(\(a, b\) => a\._sevOrder - b\._sevOrder\);",
        html,
        flags=re.DOTALL,
    )
    assert order is not None, "dashboard severity-order production code not found"
    assert hot_path is not None, "dashboard filter/sort production hot path not found"

    script = f"""
const ALL = {json.dumps(findings)};
let filterSev = {json.dumps(severity)};
let query = {json.dumps(query)};
{order.group(0)}
const filtered = [];
{hot_path.group('body')}
filtered.sort((a, b) => a._sevOrder - b._sevOrder);
process.stdout.write(JSON.stringify(filtered.map(({{f, i}}) => ({{file: f.file, i}}))));
"""
    completed = subprocess.run(
        ["node", "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def test_shipped_filter_preserves_legacy_severity_order_and_source_indexes():
    """Unknown/missing severities retain legacy -1 ordering and original indexes."""
    findings = [
        {"severity": "INFO", "file": "info"},
        {"severity": "CRITICAL", "file": "critical"},
        {"severity": "MISSING", "file": "missing-value"},
        {"file": "missing-field"},
        {"severity": "HIGH", "file": "high"},
        {"severity": "UNKNOWN", "file": "unknown"},
        {"severity": "WARNING", "file": "warning"},
    ]

    assert _run_shipped_filter(findings) == [
        {"file": "missing-value", "i": 2},
        {"file": "missing-field", "i": 3},
        {"file": "unknown", "i": 5},
        {"file": "critical", "i": 1},
        {"file": "high", "i": 4},
        {"file": "warning", "i": 6},
        {"file": "info", "i": 0},
    ]


def test_shipped_filter_composes_severity_query_and_source_index():
    """Severity and query filters compose without renumbering detail-row indexes."""
    findings = [
        {"severity": "HIGH", "file": "first.py", "message": "other", "rule_id": "x", "category": "security"},
        {"severity": "CRITICAL", "file": "second.py", "message": "needle", "rule_id": "y", "category": "security"},
        {"severity": "HIGH", "file": "third.py", "message": "needle", "rule_id": "z", "category": "security"},
    ]

    assert _run_shipped_filter(findings, severity="HIGH", query="needle") == [
        {"file": "third.py", "i": 2}
    ]


def test_tests_workflow_declares_pinned_node_runtime():
    """Hosted tests provision the JavaScript runtime required by behavioral tests."""
    workflow = _TESTS_WORKFLOW.read_text(encoding="utf-8")
    assert (
        "uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0"
        in workflow
    )
    assert 'node-version: "24.19.0"' in workflow
