"""Tests for SARIF 2.1.0 output (appguardrail_core.sarif)."""

import time

from appguardrail_core.sarif import findings_to_sarif

FINDINGS = [
    {
        "severity": "CRITICAL",
        "rule_id": "hardcoded-stripe-secret-key",
        "message": "Hardcoded Stripe key\nsecond line",
        "file": "src/pay.ts",
        "line": 12,
        "cwe": ["CWE-798"],
        "owasp": ["A05:2021"],
        "context": "app-code",
        "references": ["https://stripe.com/docs/keys"],
    },
    {
        "severity": "WARNING",
        "rule_id": "hardcoded-stripe-secret-key",
        "message": "Hardcoded Stripe key",
        "file": "src/other.ts",
        "line": 3,
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
]


def test_sarif_shape_and_version():
    log = findings_to_sarif(FINDINGS, tool_version="1.2.3")
    assert log["version"] == "2.1.0"
    assert log["$schema"].endswith("sarif-2.1.0.json")
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "AppGuardrail"
    assert run["tool"]["driver"]["version"] == "1.2.3"
    assert len(run["results"]) == 3


def test_levels_and_security_severity():
    run = findings_to_sarif(FINDINGS)["runs"][0]
    levels = [r["level"] for r in run["results"]]
    assert levels == ["error", "warning", "note"]
    # rules deduped by id (stripe rule appears once), plus the note rule
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert rule_ids == ["hardcoded-stripe-secret-key", "note"]
    stripe_rule = run["tool"]["driver"]["rules"][0]
    assert stripe_rule["properties"]["security-severity"] == "9.0"
    assert "CWE-798" in stripe_rule["properties"]["tags"]


def test_location_and_deploy_blocking():
    run = findings_to_sarif(FINDINGS)["runs"][0]
    loc = run["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/pay.ts"
    assert loc["region"]["startLine"] == 12
    # CRITICAL app-code is deploy-blocking; INFO doc is not
    assert run["results"][0]["properties"]["deployBlocking"] is True
    assert run["results"][2]["properties"]["deployBlocking"] is False
    # fingerprints are stable + unique per location
    fps = {r["partialFingerprints"]["appguardrail/v1"] for r in run["results"]}
    assert len(fps) == 3


def test_empty_findings_valid():
    run = findings_to_sarif([])["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_malformed_message_and_line_use_safe_defaults():
    run = findings_to_sarif(
        [
            {
                "rule_id": "   ",
                "message": " \n\t ",
                "file": "   ",
                "line": "not-a-number",
            }
        ]
    )["runs"][0]
    assert run["tool"]["driver"]["rules"][0]["id"] == "unknown-rule"
    assert run["results"][0]["message"]["text"] == "No message provided."
    location = run["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "n/a"
    assert location["region"]["startLine"] == 1


def test_malformed_metadata_is_discarded_and_string_metadata_is_normalized():
    malformed = {
        "rule_id": "malformed",
        "severity": "INFO",
        "message": "safe",
        "file": "x.py",
        "references": [5],
        "cwe": 5,
        "owasp": {"bad": "shape"},
    }
    string_metadata = {
        "rule_id": "string-metadata",
        "severity": "INFO",
        "message": "safe",
        "file": "y.py",
        "references": "https://example.test/help",
        "cwe": "CWE-400",
    }
    rules = findings_to_sarif([malformed, string_metadata])["runs"][0]["tool"][
        "driver"
    ]["rules"]
    assert rules[0]["helpUri"].startswith("https://github.com/")
    assert rules[0]["properties"]["tags"] == ["security", "misconfig"]
    assert rules[1]["helpUri"] == "https://example.test/help"
    assert "CWE-400" in rules[1]["properties"]["tags"]


def test_unique_rule_indexing_remains_linear_at_large_input():
    findings = [
        {
            "rule_id": f"external-{index}",
            "severity": "INFO",
            "message": "message",
            "file": "x.py",
            "line": 1,
        }
        for index in range(50_000)
    ]
    started = time.monotonic()
    results = findings_to_sarif(findings)["runs"][0]["results"]
    elapsed = time.monotonic() - started
    assert results[-1]["ruleIndex"] == 49_999
    assert elapsed < 8.0
