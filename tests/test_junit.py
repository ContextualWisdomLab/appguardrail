"""Tests for JUnit XML output (appguardrail_core.junit)."""

from xml.dom import minidom

from appguardrail_core.junit import findings_to_junit

FINDINGS = [
    {"severity": "CRITICAL", "rule_id": "secret", "file": "a.ts", "line": 3,
     "message": "hardcoded <key> & stuff", "category": "secrets", "context": "app-code"},
    {"severity": "HIGH", "rule_id": "rls", "file": "b.sql", "line": 1,
     "message": "RLS off", "context": "app-code"},
    {"severity": "INFO", "rule_id": "note", "file": "README.md", "line": 1,
     "message": "fyi", "context": "doc"},
]


def test_well_formed_and_counts():
    xml = findings_to_junit(FINDINGS)
    doc = minidom.parseString(xml)  # raises if malformed
    ts = doc.getElementsByTagName("testsuites")[0]
    assert ts.getAttribute("tests") == "3"
    assert ts.getAttribute("failures") == "2"  # 2 blocking (CRIT+HIGH app-code)
    assert doc.getElementsByTagName("testcase").length == 3


def test_only_blocking_are_failures():
    doc = minidom.parseString(findings_to_junit(FINDINGS))
    failures = doc.getElementsByTagName("failure")
    assert failures.length == 2
    # the INFO/doc finding is a non-failure testcase
    outs = doc.getElementsByTagName("system-out")
    assert outs.length == 1


def test_xml_escaping():
    xml = findings_to_junit(FINDINGS)
    assert "<key>" not in xml.replace("&lt;key&gt;", "")  # angle brackets escaped
    assert "&amp;" in xml  # the & in the message escaped


def test_empty():
    doc = minidom.parseString(findings_to_junit([]))
    ts = doc.getElementsByTagName("testsuites")[0]
    assert ts.getAttribute("tests") == "0" and ts.getAttribute("failures") == "0"
