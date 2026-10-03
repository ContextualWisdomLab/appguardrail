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

import re
from typing import Any, Iterable
from urllib.parse import urlsplit

from .findings import is_deploy_blocking, normalize_findings

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF result levels + GitHub's security-severity score (0-10) so the Security
# tab ranks findings the way AppGuardrail's deploy gate does.
_LEVEL = {"CRITICAL": "error", "HIGH": "error", "WARNING": "warning", "INFO": "note"}
_SECURITY_SEVERITY = {"CRITICAL": "9.0", "HIGH": "7.0", "WARNING": "4.0", "INFO": "2.0"}

_OWASP_HELP_URIS = {
    "OWASP A01:2021 - Broken Access Control": (
        "https://top10.owasp.org/A01_2021-Broken_Access_Control/"
    ),
    "OWASP A03:2021 - Injection": "https://top10.owasp.org/A03_2021-Injection/",
    "OWASP A05:2021 - Security Misconfiguration": (
        "https://top10.owasp.org/A05_2021-Security_Misconfiguration/"
    ),
    "OWASP A06:2021 - Vulnerable and Outdated Components": (
        "https://top10.owasp.org/A06_2021-Vulnerable_and_Outdated_Components/"
    ),
    "OWASP A07:2021 - Identification and Authentication Failures": (
        "https://top10.owasp.org/"
        "A07_2021-Identification_and_Authentication_Failures/"
    ),
    "OWASP A08:2021 - Software and Data Integrity Failures": (
        "https://top10.owasp.org/"
        "A08_2021-Software_and_Data_Integrity_Failures/"
    ),
    "OWASP A10:2021 - Server-Side Request Forgery": (
        "https://top10.owasp.org/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"
    ),
}


def _tags(finding: dict[str, Any]) -> list[str]:
    tags = ["security", str(finding.get("category") or "misconfig")]
    tags.extend(str(t) for t in finding.get("cwe") or ())
    tags.extend(str(t) for t in finding.get("owasp") or ())
    return tags


def _help_uri(references: Iterable[Any]) -> str | None:
    """Return the first absolute web URI represented by a rule reference."""
    for reference in references:
        candidate = _OWASP_HELP_URIS.get(str(reference), str(reference).strip())
        if any(
            ord(character) <= 0x20 or ord(character) == 0x7F
            for character in candidate
        ):
            continue
        if re.search(r"%(?![0-9A-Fa-f]{2})", candidate):
            continue
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            continue
        if parsed.scheme in {"http", "https"} and parsed.netloc and parsed.hostname:
            return candidate
    return None


def findings_to_sarif(
    findings: Iterable[dict[str, Any]], *, tool_version: str = "0.0.0"
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log from AppGuardrail findings."""
    normalized = normalize_findings(findings)

    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in normalized:
        rule_id = f["rule_id"]
        severity = f["severity"]
        refs = f.get("references") or ()
        if rule_id not in rules:
            rule: dict[str, Any] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {
                    "text": f["message"].strip().splitlines()[0][:200]
                },
                "fullDescription": {"text": f["message"].strip()},
                "defaultConfiguration": {"level": _LEVEL.get(severity, "note")},
                "properties": {
                    "tags": _tags(f),
                    "security-severity": _SECURITY_SEVERITY.get(severity, "2.0"),
                },
            }
            if refs:
                rule["help"] = {"text": "\n".join(str(ref) for ref in refs)}
            help_uri = _help_uri(refs)
            if help_uri is not None:
                rule["helpUri"] = help_uri
            rules[rule_id] = rule

        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": list(rules).index(rule_id),
                "level": _LEVEL.get(severity, "note"),
                "message": {"text": f["message"].strip()},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f["file"]},
                            "region": {"startLine": max(1, int(f["line"] or 1))},
                        }
                    }
                ],
                # Stable across runs so code scanning can track/dedupe alerts.
                "partialFingerprints": {
                    "appguardrail/v1": f"{rule_id}:{f['file']}:{f['line']}"
                },
                "properties": {
                    "severity": severity,
                    "context": f.get("context") or "app-code",
                    "deployBlocking": is_deploy_blocking(f),
                    "remediation": f.get("remediation") or "",
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
    assert log["version"] == "2.1.0"
    assert run["tool"]["driver"]["version"] == "1.2.3"
    assert len(run["results"]) == 2
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["properties"]["deployBlocking"] is True
    assert run["results"][1]["level"] == "note"
    assert run["results"][1]["properties"]["deployBlocking"] is False
    # rules deduped, security-severity present for GitHub ranking
    assert len(run["tool"]["driver"]["rules"]) == 2
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "9.0"
    print("sarif self-check OK")
