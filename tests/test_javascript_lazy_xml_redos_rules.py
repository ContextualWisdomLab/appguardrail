"""Regression tests for bounded detection of lazy XML block regexes."""

import hashlib
from pathlib import Path
import re

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "javascript-xml-lazy-dotall-block-redos"
_SOURCE_REPOSITORY = "ContextualWisdomLab/scopeweave"
_VULNERABLE_HEAD_SHA = "a756b7e3cf486cba0930c1a482c6a30e0df958f5"
_VULNERABLE_BLOB_SHA = "7e44932baf55854d18f7ef9da0937d14f982b9ed"
_FIXED_HEAD_SHA = "bd9a51584f1cf37f4f4446022a90775a20152edf"
_FIXED_BLOB_SHA = "9016cfbf157b812a738bf8f7f9063f43b4af2737"
_VULNERABLE_SOURCE_LINES = (741, 780)
_FIXED_SOURCE_LINES = (741, 809)
_VULNERABLE_SECTION_SHA256 = "491922167e389e8fa4aae8dc875d203802521193ba9afafbd621e7a1202a5ccf"
_FIXED_SECTION_SHA256 = "25119bfbd5f2b57d583aad7161aa218de7b13d0533dfd9ea0eb00ddf6f9a9f53"
_FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "scopeweave" / "javascript_lazy_xml_redos"
_VULNERABLE_FIXTURE = _FIXTURE_ROOT / f"{_VULNERABLE_HEAD_SHA}-parseMsProjectXml.js"
_FIXED_FIXTURE = _FIXTURE_ROOT / f"{_FIXED_HEAD_SHA}-parseMsProjectXml.js"
_VULNERABLE_SOURCE = _VULNERABLE_FIXTURE.read_text(encoding="utf-8")
_FIXED_SOURCE = _FIXED_FIXTURE.read_text(encoding="utf-8")
_PCRE2_LARGE_BOUNDED_SCAN = re.compile(r"\{0,[1-9][0-9]{3,}\}")

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

_SIX_DIGIT_BOUND_SOURCE = r"""
function parseWithSixDigitCap(xml) {
  if (xml.length > 999999) throw new Error('too large');
  return xml.match(/<Task>[\s\S]*?<\/Task>/g) || [];
}
"""

_NON_TERMINATING_LENGTH_GUARD_SOURCE = r"""
function parseAfterLoggingLargeInput(xml) {
  if (xml.length > 1024) console.debug('large input');
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
    """Keep detector efficacy tied to immutable upstream source identities."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/scopeweave"
    assert _VULNERABLE_HEAD_SHA == "a756b7e3cf486cba0930c1a482c6a30e0df958f5"
    assert _VULNERABLE_BLOB_SHA == "7e44932baf55854d18f7ef9da0937d14f982b9ed"
    assert _FIXED_HEAD_SHA == "bd9a51584f1cf37f4f4446022a90775a20152edf"
    assert _FIXED_BLOB_SHA == "9016cfbf157b812a738bf8f7f9063f43b4af2737"
    assert _VULNERABLE_SOURCE_LINES == (741, 780)
    assert _FIXED_SOURCE_LINES == (741, 809)


def test_source_sections_are_immutable_exact_replays() -> None:
    """Reject any drift in the committed upstream function-section fixtures."""
    vulnerable_digest = hashlib.sha256(_VULNERABLE_FIXTURE.read_bytes()).hexdigest()
    fixed_digest = hashlib.sha256(_FIXED_FIXTURE.read_bytes()).hexdigest()
    assert vulnerable_digest == _VULNERABLE_SECTION_SHA256
    assert fixed_digest == _FIXED_SECTION_SHA256


def test_rule_detects_scopeweave_lazy_xml_block_collection() -> None:
    """Detect the exact vulnerable ScopeWeave function replay."""
    rule = _rule()
    assert rule["severity"] == "HIGH"
    assert rule["pattern"].search(_VULNERABLE_SOURCE)


def test_rule_declares_xml_and_lazy_dotall_prefilter() -> None:
    """Avoid evaluating the multiline detector for unrelated JavaScript."""
    assert _rule()["required_substrings"] == ("[\\s\\S]*?", ".match")


def test_rule_avoids_large_bounded_scans_that_break_semgrep_pcre2() -> None:
    """Keep the shared YAML rule compilable by Semgrep's PCRE2 regex engine."""
    assert not _PCRE2_LARGE_BOUNDED_SCAN.search(_rule()["pattern"].pattern)


def test_rule_ignores_reviewed_linear_scanner_fix() -> None:
    """Do not flag the exact reviewed ScopeWeave function replay."""
    assert not _rule()["pattern"].search(_FIXED_SOURCE)


def test_rule_ignores_explicitly_size_bounded_lazy_regex() -> None:
    """Do not flag a locally bounded fixture parser with a small input cap."""
    assert not _rule()["pattern"].search(_BOUNDED_REGEX_SOURCE)


def test_scan_flags_large_bound_as_not_meaningfully_bounded(tmp_path: Path) -> None:
    """Do not let a multi-megabyte cap suppress this quadratic-risk source shape."""
    findings = _findings(tmp_path, _LARGE_BOUND_SOURCE)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_scan_flags_six_digit_bound_as_not_meaningfully_bounded(tmp_path: Path) -> None:
    """A six-digit cap is outside the detector's intentionally small safe bound."""
    findings = _findings(tmp_path, _SIX_DIGIT_BOUND_SOURCE)
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_scan_flags_length_guard_that_does_not_terminate(tmp_path: Path) -> None:
    """A logging-only length branch cannot prevent the regex sink from executing."""
    findings = _findings(tmp_path, _NON_TERMINATING_LENGTH_GUARD_SOURCE)
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
    """Exercise the production scanner on the exact vulnerable source replay."""
    findings = _findings(tmp_path, _VULNERABLE_SOURCE)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "HIGH"
    assert finding["source"] == "appguardrail-rule"
    assert finding["confidence"] == "high"
    assert "regular expression" in finding["message"].lower()
    assert "1333" in " ".join(finding["cwe"])


def test_scan_file_does_not_flag_reviewed_fix(tmp_path: Path) -> None:
    """Keep the exact fixed ScopeWeave source replay clean in production scan."""
    assert _findings(tmp_path, _FIXED_SOURCE) == []
