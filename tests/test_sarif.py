"""Tests for SARIF 2.1.0 output (appguardrail_core.sarif)."""

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


# ---- robustness: one malformed finding must not sink the report ----

def test_non_integer_line_does_not_crash():
    from appguardrail_core.sarif import findings_to_sarif
    log = findings_to_sarif([
        {"severity": "HIGH", "rule_id": "trivy-range", "message": "range",
         "file": "a.tf", "line": "12-14", "context": "app-code"},
        {"severity": "INFO", "rule_id": "na", "message": "x",
         "file": "b", "line": "n/a", "context": "doc"},
    ])
    regions = [r["locations"][0]["physicalLocation"]["region"]["startLine"]
               for r in log["runs"][0]["results"]]
    assert regions == [1, 1]  # coerced, not crashed


def test_blank_message_gets_fallback_short_description():
    from appguardrail_core.sarif import findings_to_sarif
    log = findings_to_sarif([
        {"severity": "HIGH", "rule_id": "blank", "message": "   ",
         "file": "a", "line": 3, "context": "app-code"},
    ])
    rule = log["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["shortDescription"]["text"]  # non-empty, no IndexError


def test_private_index_not_leaked_and_ruleindex_correct():
    from appguardrail_core.sarif import findings_to_sarif
    log = findings_to_sarif([
        {"severity": "HIGH", "rule_id": "a", "message": "m", "file": "f", "line": 1, "context": "app-code"},
        {"severity": "HIGH", "rule_id": "b", "message": "m", "file": "f", "line": 2, "context": "app-code"},
        {"severity": "HIGH", "rule_id": "a", "message": "m", "file": "f", "line": 3, "context": "app-code"},
    ])
    run = log["runs"][0]
    assert all("_index" not in r for r in run["tool"]["driver"]["rules"])
    assert [r["ruleIndex"] for r in run["results"]] == [0, 1, 0]  # deduped, stable
