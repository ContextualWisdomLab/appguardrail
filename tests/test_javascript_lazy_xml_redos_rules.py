"""Regression tests for bounded detection of lazy XML block regexes."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "javascript-xml-lazy-dotall-block-redos"
_SOURCE_REPOSITORY = "ContextualWisdomLab/scopeweave"
_VULNERABLE_HEAD_SHA = "a756b7e3cf486cba0930c1a482c6a30e0df958f5"
_VULNERABLE_BLOB_SHA = "7e44932baf55854d18f7ef9da0937d14f982b9ed"
_FIXED_HEAD_SHA = "bd9a51584f1cf37f4f4446022a90775a20152edf"
_FIXED_BLOB_SHA = "9016cfbf157b812a738bf8f7f9063f43b4af2737"

_VULNERABLE_SOURCE = r"""
export function parseMsProjectXml(xml) {
  const tasks = [];
  const blocks = xml.match(/<Task>[\s\S]*?<\/Task>/g) || [];
  for (const block of blocks) {
    const preds = [...block.matchAll(/<PredecessorLink>[\s\S]*?<PredecessorUID>(\d+)<\/PredecessorUID>[\s\S]*?<\/PredecessorLink>/g)]
      .map((m) => `msp-${m[1]}`);
    tasks.push({ predecessors: preds.join(',') });
  }
  return tasks;
}
"""

_FIXED_SOURCE = r"""
export function parseMsProjectXml(xml) {
  const collectBlocks = (source, openTag, closeTag) => {
    const out = [];
    let from = 0;
    for (;;) {
      const start = source.indexOf(openTag, from);
      if (start === -1) break;
      const contentStart = start + openTag.length;
      const end = source.indexOf(closeTag, contentStart);
      if (end === -1) break;
      out.push(source.slice(start, end + closeTag.length));
      from = end + closeTag.length;
    }
    return out;
  };
  return collectBlocks(String(xml || ''), '<Task>', '</Task>');
}
"""

_BOUNDED_REGEX_SOURCE = r"""
function parseSmallInternalFixture(xml) {
  if (xml.length > 1024) throw new Error('too large');
  return xml.match(/<Task>[\s\S]*?<\/Task>/g) || [];
}
"""

_LARGE_BOUND_SOURCE = r"""
function parseEffectivelyUnboundedXml(xml) {
  if (xml.length > 9999999) throw new Error('too large');
  return xml.match(/<Task>[\s\S]*?<\/Task>/g) || [];
}
"""

_POST_SINK_BOUND_SOURCE = r"""
function parseBeforeCheckingLength(xml) {
  const blocks = xml.match(/<Task>[\s\S]*?<\/Task>/g) || [];
  if (xml.length > 1024) throw new Error('too large');
  return blocks;
}
"""

_NON_ENFORCING_LENGTH_CHECK_SOURCE = r"""
function parseAfterTelemetryOnly(xml) {
  console.debug('small?', xml.length <= 1024);
  return xml.match(/<Task>[\s\S]*?<\/Task>/g) || [];
}
"""

_NON_XML_SOURCE = r"""
function scanText(text) {
  return text.match(/[\s\S]*?/g) || [];
}
"""


def _rule():
    """Return the packaged source-derived XML lazy-block detector."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1, f"expected one loaded rule for {_RULE_ID}"
    return matches[0]


def _findings(tmp_path: Path, source: str) -> list[dict]:
    """Scan JavaScript source with the production scanner entrypoint."""
    source_file = tmp_path / "cloud-sync.js"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_source_provenance_pins_vulnerable_and_fixed_scopeweave_blobs() -> None:
    """Keep detector efficacy tied to immutable source identities."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/scopeweave"
    assert _VULNERABLE_HEAD_SHA == "a756b7e3cf486cba0930c1a482c6a30e0df958f5"
    assert _VULNERABLE_BLOB_SHA == "7e44932baf55854d18f7ef9da0937d14f982b9ed"
    assert _FIXED_HEAD_SHA == "bd9a51584f1cf37f4f4446022a90775a20152edf"
    assert _FIXED_BLOB_SHA == "9016cfbf157b812a738bf8f7f9063f43b4af2737"


def test_rule_detects_scopeweave_lazy_xml_block_collection() -> None:
    """Detect unbounded lazy dot-all block collection over XML-like input."""
    rule = _rule()
    assert rule["severity"] == "HIGH"
    assert rule["pattern"].search(_VULNERABLE_SOURCE)


def test_rule_declares_xml_and_lazy_dotall_prefilter() -> None:
    """Avoid evaluating the multiline detector for unrelated JavaScript."""
    assert _rule()["required_substrings"] == ("[\\s\\S]*?", ".match")


def test_rule_ignores_reviewed_linear_scanner_fix() -> None:
    """Do not flag the source-reviewed indexOf/slice replacement."""
    assert not _rule()["pattern"].search(_FIXED_SOURCE)


def test_rule_ignores_explicitly_size_bounded_lazy_regex() -> None:
    """Do not flag a locally bounded fixture parser with a small input cap."""
    assert not _rule()["pattern"].search(_BOUNDED_REGEX_SOURCE)


def test_scan_flags_large_bound_as_not_meaningfully_bounded(tmp_path: Path) -> None:
    """Do not let a multi-megabyte cap suppress this quadratic-risk source shape."""
    findings = _findings(tmp_path, _LARGE_BOUND_SOURCE)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_scan_flags_length_check_that_occurs_after_regex_sink(tmp_path: Path) -> None:
    """A post-sink guard cannot protect the already-executed regex operation."""
    findings = _findings(tmp_path, _POST_SINK_BOUND_SOURCE)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_scan_flags_non_enforcing_length_comparison(tmp_path: Path) -> None:
    """A telemetry-only comparison is not evidence that input was bounded."""
    findings = _findings(tmp_path, _NON_ENFORCING_LENGTH_CHECK_SOURCE)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_rule_ignores_non_xml_lazy_regex() -> None:
    """Require XML-like opening and closing tag delimiters."""
    assert not _rule()["pattern"].search(_NON_XML_SOURCE)


def test_scan_file_emits_high_redos_finding(tmp_path: Path) -> None:
    """Exercise the production scanner on the vulnerable source replay."""
    findings = _findings(tmp_path, _VULNERABLE_SOURCE)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "HIGH"
    assert finding["source"] == "appguardrail-rule"
    assert finding["confidence"] == "high"
    assert "regular expression" in finding["message"].lower()
    assert "1333" in " ".join(finding["cwe"])


def test_scan_file_does_not_flag_reviewed_fix(tmp_path: Path) -> None:
    """Keep the exact linear source fix clean through production scan."""
    assert _findings(tmp_path, _FIXED_SOURCE) == []
