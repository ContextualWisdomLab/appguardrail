"""Render AppGuardrail findings as JUnit XML.

Most CI systems (GitLab, Jenkins, CircleCI, Azure Pipelines, Buildkite) render
a JUnit XML report as a first-class test summary. Emitting it lets a scan show
up as pass/fail test cases in the CI UI — one <testcase> per finding, marked
<failure> when it is deploy-blocking.

Stdlib only (xml.sax.saxutils for escaping).
"""

from __future__ import annotations

from typing import Any, Iterable
from xml.sax.saxutils import escape, quoteattr

from .findings import is_deploy_blocking, normalize_findings


def _attr(value: Any) -> str:
    return quoteattr(str(value))


def findings_to_junit(findings: Iterable[dict[str, Any]]) -> str:
    """Build a JUnit XML string: one testcase per finding, failure if blocking."""
    normalized = list(normalize_findings(findings))
    failures = sum(1 for f in normalized if is_deploy_blocking(f))

    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append(
        "<testsuites "
        f"name={_attr('AppGuardrail')} "
        f"tests={_attr(len(normalized))} "
        f"failures={_attr(failures)}>"
    )
    lines.append(
        "  <testsuite "
        f"name={_attr('appguardrail.scan')} "
        f"tests={_attr(len(normalized))} "
        f"failures={_attr(failures)}>"
    )
    for finding in normalized:
        name = f"{finding['rule_id']} at {finding['file']}:{finding['line']}"
        classname = finding.get("category") or "misconfig"
        blocking = is_deploy_blocking(finding)
        lines.append(
            f"    <testcase classname={_attr(classname)} name={_attr(name)}>"
        )
        if blocking:
            message = finding["message"].strip().splitlines()[0][:200]
            body = (
                f"{finding['severity']} {finding['rule_id']}\n"
                f"{finding['message'].strip()}\n"
                f"File: {finding['file']}:{finding['line']}"
            )
            lines.append(
                f"      <failure message={_attr(message)} "
                f"type={_attr(finding['severity'])}>{escape(body)}</failure>"
            )
        else:
            # Non-blocking findings are recorded but not failures.
            lines.append(f"      <system-out>{escape(finding['severity'])}</system-out>")
        lines.append("    </testcase>")
    lines.append("  </testsuite>")
    lines.append("</testsuites>")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":  # pragma: no cover - self-check
    from xml.dom import minidom

    xml = findings_to_junit(
        [
            {"severity": "CRITICAL", "rule_id": "secret", "file": "a.ts", "line": 3,
             "message": "hardcoded <key>", "category": "secrets", "context": "app-code"},
            {"severity": "INFO", "rule_id": "note", "file": "README.md", "line": 1,
             "message": "fyi", "context": "doc"},
        ]
    )
    doc = minidom.parseString(xml)  # must be well-formed XML
    assert doc.getElementsByTagName("testcase").length == 2
    assert doc.getElementsByTagName("failure").length == 1  # only the blocking one
    assert "&lt;key&gt;" in xml  # message escaped
    print("junit self-check OK")
