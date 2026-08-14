"""Source-derived regression tests for CSV formula-prefix neutralization."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "javascript-csv-formula-leading-whitespace-bypass"
_SOURCE_REPOSITORY = "ContextualWisdomLab/scopeweave"
_VULNERABLE_HEAD_SHA = "a756b7e3cf486cba0930c1a482c6a30e0df958f5"
_VULNERABLE_BLOB_SHA = "926d528d17b7ae39ab89001657a21f7ef30af743"
_FIXED_HEAD_SHA = "bd9a51584f1cf37f4f4446022a90775a20152edf"
_FIXED_BLOB_SHA = "13d95e5dfa0719451a5b4a6d952467994172b79a"

_VULNERABLE_SOURCE = r"""
app.get('/api/orgs/:id/audit', requireAuth, (c) => {
  const events = rows.map((r) => ({ ...r }));
  if (c.req.query('format') === 'csv') {
    const csvCell = (v) => {
      let s = v == null ? '' : String(v);
      if (/^[=+\-@|]/.test(s)) s = `'${s}`;
      return /[\",\n]/.test(s) ? `\"${s.replace(/\"/g, '\"\"')}\"` : s;
    };
    const lines = [['id', 'actorEmail'].join(',')];
    for (const event of events) lines.push([event.id, event.actorEmail].map(csvCell).join(','));
    return c.text(lines.join('\\r\\n') + '\\r\\n', 200, {
      'content-type': 'text/csv; charset=utf-8',
    });
  }
});
"""

_FIXED_SOURCE = r"""
app.get('/api/orgs/:id/audit', requireAuth, (c) => {
  const events = rows.map((r) => ({ ...r }));
  if (c.req.query('format') === 'csv') {
    const csvCell = (v) => {
      let s = v == null ? '' : String(v);
      if (/^\s*[=+\-@|]/.test(s)) s = `'${s}`;
      return /[\",\n]/.test(s) ? `\"${s.replace(/\"/g, '\"\"')}\"` : s;
    };
    const lines = [['id', 'actorEmail'].join(',')];
    for (const event of events) lines.push([event.id, event.actorEmail].map(csvCell).join(','));
    return c.text(lines.join('\\r\\n') + '\\r\\n', 200, {
      'content-type': 'text/csv; charset=utf-8',
    });
  }
});
"""

_NON_CSV_SOURCE = r"""
export function showFormula(value) {
  let s = String(value);
  if (/^[=+\-@|]/.test(s)) s = `'${s}`;
  return s;
}
"""

_NO_NEUTRALIZER_SOURCE = r"""
export function exportCsv(rows) {
  return rows.map((row) => row.join(',')).join('\\r\\n');
}
"""


def _rule():
    """Return the single packaged CSV formula neutralization detector."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1, f"expected one loaded rule for {_RULE_ID}"
    return matches[0]


def _findings(tmp_path: Path, source: str) -> list[dict]:
    """Execute the production scanner and isolate this detector family."""
    source_file = tmp_path / "app.mjs"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_source_provenance_pins_vulnerable_and_fixed_scopeweave_blobs() -> None:
    """Keep the detector tied to immutable source revisions and blobs."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/scopeweave"
    assert _VULNERABLE_HEAD_SHA == "a756b7e3cf486cba0930c1a482c6a30e0df958f5"
    assert _VULNERABLE_BLOB_SHA == "926d528d17b7ae39ab89001657a21f7ef30af743"
    assert _FIXED_HEAD_SHA == "bd9a51584f1cf37f4f4446022a90775a20152edf"
    assert _FIXED_BLOB_SHA == "13d95e5dfa0719451a5b4a6d952467994172b79a"


def test_rule_detects_scopeweave_leading_whitespace_formula_bypass() -> None:
    """Detect a CSV formula guard that checks only the first raw character."""
    rule = _rule()
    assert rule["severity"] == "HIGH"
    assert rule["pattern"].search(_VULNERABLE_SOURCE)


def test_rule_declares_csv_context_prefilter() -> None:
    """Avoid evaluating the multiline signature outside likely CSV exporters."""
    assert _rule()["required_substrings"] == (
        "text/csv",
        ".test(",
        ".join(',')",
    )


def test_rule_ignores_reviewed_whitespace_aware_fix() -> None:
    """Do not flag the reviewed guard that consumes leading whitespace."""
    assert not _rule()["pattern"].search(_FIXED_SOURCE)


def test_rule_ignores_same_guard_outside_csv_export() -> None:
    """Require a CSV output sink instead of any regex-based string display."""
    assert not _rule()["pattern"].search(_NON_CSV_SOURCE)


def test_rule_does_not_claim_missing_neutralizer_dataflow() -> None:
    """Do not overclaim coverage for exporters with no recognizable guard."""
    assert not _rule()["pattern"].search(_NO_NEUTRALIZER_SOURCE)


def test_scan_file_emits_normalized_csv_formula_finding(tmp_path: Path) -> None:
    """Exercise the exact production scanner on the vulnerable source replay."""
    findings = _findings(tmp_path, _VULNERABLE_SOURCE)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "HIGH"
    assert finding["source"] == "appguardrail-rule"
    assert finding["confidence"] == "high"
    assert "1236" in " ".join(finding["cwe"])
    assert "csv" in finding["message"].lower()


def test_scan_file_does_not_flag_reviewed_fix(tmp_path: Path) -> None:
    """Keep the source-reviewed fixed exporter clean through production scan."""
    assert _findings(tmp_path, _FIXED_SOURCE) == []
