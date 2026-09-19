"""Tests for SARIF 2.1.0 output (appguardrail_core.sarif)."""

from urllib.parse import urlsplit

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
    assert stripe_rule["helpUri"] == "https://stripe.com/docs/keys"


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


def test_help_uri_is_a_uri_and_reference_labels_remain_readable():
    """SARIF helpUri values are URLs, while labels remain in help text."""
    findings = [
        {
            "severity": "WARNING",
            "rule_id": "missing-authorization",
            "message": "Authorization is missing",
            "file": "src/auth.py",
            "line": 1,
            "references": ["OWASP A01:2021 - Broken Access Control"],
        },
        {
            "severity": "WARNING",
            "rule_id": "unsafe-default",
            "message": "An unsafe default is enabled",
            "file": "config.toml",
            "line": 2,
            "references": ["OWASP A05:2021 - Security Misconfiguration"],
        },
        {
            "severity": "INFO",
            "rule_id": "local-guidance",
            "message": "Review local guidance",
            "file": "README.md",
            "line": 3,
            "references": ["Internal security review guide"],
        },
    ]

    rules = findings_to_sarif(findings)["runs"][0]["tool"]["driver"]["rules"]
    assert rules[0]["helpUri"] == (
        "https://top10.owasp.org/A01_2021-Broken_Access_Control/"
    )
    assert rules[1]["helpUri"] == (
        "https://top10.owasp.org/A05_2021-Security_Misconfiguration/"
    )
    assert "helpUri" not in rules[2]
    assert rules[2]["help"]["text"] == "Internal security review guide"
    for rule in rules[:2]:
        parsed = urlsplit(rule["helpUri"])
        assert parsed.scheme == "https"
        assert parsed.netloc
        assert rule["help"]["text"].startswith("OWASP ")
