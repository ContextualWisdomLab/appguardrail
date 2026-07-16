"""Render AppGuardrail findings as SARIF 2.1.0.

SARIF is the OASIS-standard interchange format for static-analysis results.
Emitting it lets `appguardrail scan --sarif out.sarif` feed GitHub code
scanning (github/codeql-action/upload-sarif), the VS Code SARIF viewer, Azure
DevOps, and any other SARIF consumer — turning findings into native PR
annotations and Security-tab entries without a bespoke integration.

Maps the normalized `appguardrail.findings.v1` model straight to SARIF, so it
stays in lockstep with findings.py.
"""

from __future__ import annotations

from typing import Any, Iterable

from .findings import is_deploy_blocking

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF result levels + GitHub's security-severity score (0-10) so the Security
# tab ranks findings the way AppGuardrail's deploy gate does.
_LEVEL = {"CRITICAL": "error", "HIGH": "error", "WARNING": "warning", "INFO": "note"}
_SECURITY_SEVERITY = {"CRITICAL": "9.0", "HIGH": "7.0", "WARNING": "4.0", "INFO": "2.0"}


def _string_values(value: Any) -> list[str]:
    """Return non-empty strings from untrusted scalar or sequence metadata."""
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else []
    if not isinstance(value, (list, tuple, set, frozenset)):
        return []
    return [
        stripped
        for item in value
        if isinstance(item, str) and (stripped := item.strip())
    ]


def _tags(finding: dict[str, Any]) -> list[str]:
    tags = ["security", str(finding.get("category") or "misconfig")]
    tags.extend(_string_values(finding.get("cwe")))
    tags.extend(_string_values(finding.get("owasp")))
    return tags


def _nonempty_text(value: Any, fallback: str) -> str:
    """Return stripped text, replacing malformed empty values with a fallback."""
    text = str(value or "").strip()
    return text or fallback


def _start_line(value: Any) -> int:
    """Return a valid positive SARIF line number for untrusted finding input."""
    try:
        return max(1, int(value))
    except (TypeError, ValueError, OverflowError):
        return 1


def findings_to_sarif(
    findings: Iterable[dict[str, Any]], *, tool_version: str = "0.0.0"
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log from AppGuardrail findings."""
    rules: dict[str, dict[str, Any]] = {}
    rule_indices: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    for raw in findings:
        f = raw if isinstance(raw, dict) else {}
        rule_id = _nonempty_text(f.get("rule_id"), "unknown-rule")
        severity = _nonempty_text(f.get("severity"), "INFO").upper()
        message = _nonempty_text(f.get("message"), "No message provided.")
        file_name = _nonempty_text(f.get("file"), "n/a")
        line = _start_line(f.get("line"))
        refs = _string_values(f.get("references"))
        context = _nonempty_text(f.get("context"), "app-code")
        if rule_id not in rules:
            rule: dict[str, Any] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": message.splitlines()[0][:200]},
                "fullDescription": {"text": message},
                "helpUri": (
                    refs[0]
                    if refs
                    else "https://github.com/ContextualWisdomLab/appguardrail"
                ),
                "defaultConfiguration": {"level": _LEVEL.get(severity, "note")},
                "properties": {
                    "tags": _tags(f),
                    "security-severity": _SECURITY_SEVERITY.get(severity, "2.0"),
                },
            }
            rule_indices[rule_id] = len(rules)
            rules[rule_id] = rule

        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": rule_indices[rule_id],
                "level": _LEVEL.get(severity, "note"),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": file_name},
                            "region": {"startLine": line},
                        }
                    }
                ],
                # Stable across runs so code scanning can track/dedupe alerts.
                "partialFingerprints": {
                    "appguardrail/v1": f"{rule_id}:{file_name}:{line}"
                },
                "properties": {
                    "severity": severity,
                    "context": context,
                    "deployBlocking": is_deploy_blocking(
                        {"severity": severity, "context": context}
                    ),
                    "remediation": _nonempty_text(f.get("remediation"), ""),
                },
            }
        )

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AppGuardrail",
                        "informationUri": "https://github.com/ContextualWisdomLab/appguardrail",
                        "version": tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


if __name__ == "__main__":  # pragma: no cover - self-check
    # Executable module self-checks; these assertions do not validate user input.
    log = findings_to_sarif(
        [
            {
                "severity": "CRITICAL",
                "rule_id": "hardcoded-stripe-secret-key",
                "message": "Hardcoded Stripe key",
                "file": "src/pay.ts",
                "line": 12,
                "cwe": ["CWE-798"],
                "context": "app-code",
            },
            {
                "severity": "INFO",
                "rule_id": "note",
                "message": "fyi",
                "file": "README.md",
                "line": 1,
                "context": "doc",
            },
        ],
        tool_version="1.2.3",
    )
    run = log["runs"][0]
    assert log["version"] == "2.1.0"  # noqa: S101  # nosec B101
    assert run["tool"]["driver"]["version"] == "1.2.3"  # noqa: S101  # nosec B101
    assert len(run["results"]) == 2  # noqa: S101  # nosec B101
    assert run["results"][0]["level"] == "error"  # noqa: S101  # nosec B101
    assert run["results"][0]["properties"]["deployBlocking"] is True  # noqa: S101  # nosec B101
    assert run["results"][1]["level"] == "note"  # noqa: S101  # nosec B101
    assert run["results"][1]["properties"]["deployBlocking"] is False  # noqa: S101  # nosec B101
    # rules deduped, security-severity present for GitHub ranking
    assert len(run["tool"]["driver"]["rules"]) == 2  # noqa: S101  # nosec B101
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "9.0"  # noqa: S101  # nosec B101
    print("sarif self-check OK")
