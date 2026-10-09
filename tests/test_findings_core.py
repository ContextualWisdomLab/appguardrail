import pytest

from appguardrail_core.findings import (finding_sort_key, is_deploy_blocking,
                                        normalize_finding, normalize_findings,
                                        safe_report_snippet, severity_counts,
                                        severities_at_or_above)


class ExplosiveText:
    def __bool__(self):
        return True

    def __str__(self):
        raise RuntimeError("caller-controlled conversion failed")


class NonIterableReference:
    def __str__(self):
        return "fallback-reference"


class ExplosiveReferences:
    def __iter__(self):
        yield "preserved-reference"
        raise RuntimeError("caller-controlled iteration failed")


class SecretText:
    def __str__(self):
        return "Authorization: ApiKey coerced-secret-value"


class SecretLine:
    def __str__(self):
        return "Authorization: ApiKey late-coercion-secret"


def test_normalize_finding_adds_report_contract_defaults():
    finding = normalize_finding(
        {
            "severity": "high",
            "rule_id": "python-requests-verify-false",
            "message": "TLS verification disabled.",
            "file": "client.py",
            "line": 7,
            "references": "CWE-295 - Improper Certificate Validation",
            "fix_prompt": "Keep certificate verification enabled.",
        }
    )

    assert finding["severity"] == "HIGH"
    assert finding["category"] == "misconfig"
    assert finding["context"] == "app-code"
    assert finding["references"] == ("CWE-295 - Improper Certificate Validation",)
    assert finding["remediation"] == "Keep certificate verification enabled."
    assert finding["verification"] == "Rerun AppGuardrail after remediation."


def test_normalize_findings_returns_stable_tuple():
    normalized = normalize_findings(
        [
            {"rule_id": "one", "severity": "INFO"},
            {"rule_id": "two", "severity": "WARNING"},
        ]
    )

    assert isinstance(normalized, tuple)
    assert [finding["rule_id"] for finding in normalized] == ["one", "two"]


def test_normalize_finding_fails_closed_when_text_conversion_raises():
    hostile = ExplosiveText()

    finding = normalize_finding(
        {
            "severity": hostile,
            "rule_id": hostile,
            "message": hostile,
            "file": hostile,
            "category": hostile,
            "context": hostile,
            "remediation": hostile,
            "verification": hostile,
            "snippet": hostile,
            "references": [hostile],
            "owasp": [hostile],
            "cwe": [hostile],
        }
    )

    assert finding["severity"] == "INFO"
    assert finding["rule_id"] == "unknown-rule"
    assert finding["message"] == "No message provided."
    assert finding["file"] == "n/a"
    assert finding["category"] == "misconfig"
    assert finding["context"] == "app-code"
    assert finding["remediation"] == "Review and remediate this finding, then rerun AppGuardrail."
    assert finding["verification"] == "Rerun AppGuardrail after remediation."
    assert finding["snippet"] == ""
    assert finding["references"] == ()
    assert finding["owasp"] == ()
    assert finding["cwe"] == ()


def test_finding_helpers_fail_closed_when_text_conversion_raises():
    hostile = ExplosiveText()

    assert severity_counts([{"severity": hostile}]) == {
        "CRITICAL": 0,
        "HIGH": 0,
        "WARNING": 0,
        "INFO": 1,
    }
    assert not is_deploy_blocking({"severity": hostile, "context": hostile})
    assert finding_sort_key(
        {"severity": hostile, "category": hostile, "rule_id": hostile}
    ) == (3, "misconfig", "unknown-rule")
    assert safe_report_snippet(hostile) == ""


def test_severity_counts_folds_unknown_values_into_info():
    counts = severity_counts(
        [
            {"severity": "CRITICAL"},
            {"severity": "medium"},
            {"severity": ""},
            {},
        ]
    )

    assert counts == {"CRITICAL": 1, "HIGH": 0, "WARNING": 0, "INFO": 3}


def test_finding_reference_and_severity_fallback_edges():
    fallback = normalize_finding({"references": NonIterableReference()})
    failed = normalize_finding({"references": ExplosiveText()})
    partial = normalize_finding({"references": ExplosiveReferences()})

    assert fallback["references"] == ("fallback-reference",)
    assert failed["references"] == ()
    assert partial["references"] == ("preserved-reference",)
    assert severities_at_or_above("not-a-severity") == {"CRITICAL", "HIGH"}
    assert severities_at_or_above("WARNING") == {"CRITICAL", "HIGH", "WARNING"}


def test_is_deploy_blocking_uses_context_and_case_insensitive_severity():
    assert is_deploy_blocking({"severity": "critical", "context": "app-code"})
    assert is_deploy_blocking({"severity": "HIGH"})
    assert not is_deploy_blocking({"severity": "HIGH", "context": "doc"})
    assert not is_deploy_blocking({"severity": "WARNING", "context": "app-code"})


def test_finding_sort_key_orders_by_deploy_severity_then_category_and_rule():
    findings = [
        {"severity": "INFO", "category": "z", "rule_id": "z"},
        {"severity": "HIGH", "category": "authz", "rule_id": "b"},
        {"severity": "CRITICAL", "category": "secrets", "rule_id": "a"},
        {"severity": "HIGH", "category": "authz", "rule_id": "a"},
    ]

    ordered = sorted(findings, key=finding_sort_key)

    assert [finding["rule_id"] for finding in ordered] == ["a", "a", "b", "z"]


def test_safe_report_snippet_trims_without_changing_short_text():
    assert safe_report_snippet("short evidence") == "short evidence"
    assert safe_report_snippet("x" * 410, max_len=20) == "x" * 20 + "\n...[truncated]"


def test_normalize_finding_suppresses_imported_secret_evidence():
    synthetic_secret = "synthetic-secret-value-for-regression-only"

    finding = normalize_finding(
        {
            "rule_id": "external-finding-42",
            "category": "secrets",
            "snippet": f'password="{synthetic_secret}"',
        }
    )

    assert finding["snippet"] == "[REDACTED: sensitive match suppressed]"
    assert synthetic_secret not in finding["snippet"]


def test_normalize_finding_suppresses_sensitive_rule_with_wrong_category():
    synthetic_secret = "synthetic-secret-value-for-regression-only"

    finding = normalize_finding(
        {
            "rule_id": "external-hardcoded-credential",
            "category": "misconfig",
            "snippet": synthetic_secret,
        }
    )

    assert finding["snippet"] == "[REDACTED: sensitive match suppressed]"
    assert synthetic_secret not in finding["snippet"]


def test_normalize_finding_redacts_obvious_secret_in_nonsecret_category():
    synthetic_token = "synthetic-bearer-token-for-regression-only"

    finding = normalize_finding(
        {
            "rule_id": "external-http-header",
            "category": "misconfig",
            "snippet": f"Authorization: Bearer {synthetic_token}",
        }
    )

    assert finding["snippet"] == "Authorization: [REDACTED]"
    assert synthetic_token not in finding["snippet"]


def test_normalize_finding_sanitizes_all_emitted_and_extension_fields():
    synthetic_token = "ghp_" + "a" * 24
    finding = normalize_finding(
        {
            "rule_id": "external-finding-42",
            "category": "misconfig",
            "message": f"Observed token={synthetic_token}",
            "file": f"evidence/{synthetic_token}.txt",
            "remediation": f"Rotate password='{synthetic_token}'",
            "verification": f"Reject Authorization: Bearer {synthetic_token}",
            "references": [f"https://example.invalid/{synthetic_token}"],
            "raw_evidence": {"body": synthetic_token},
            "provider_metadata": {
                "authorization": synthetic_token,
                "snippet": "opaque-unknown-secret",
                synthetic_token: "present",
            },
            "raw": "opaque-raw-value",
            "raw_response": "opaque-response-value",
            "credentials": ["opaque-credential-value"],
            "credentialData": {"value": "opaque-credential-data"},
            "apiKey": 123456789,
        }
    )

    assert synthetic_token not in repr(finding)
    assert finding["raw_evidence"] == "[REDACTED]"
    assert finding["provider_metadata"]["authorization"] == "[REDACTED]"
    assert finding["provider_metadata"]["snippet"] == "[REDACTED]"
    assert synthetic_token not in finding["provider_metadata"]
    assert "[REDACTED]" in finding["provider_metadata"]
    assert finding["raw"] == "[REDACTED]"
    assert finding["raw_response"] == "[REDACTED]"
    assert finding["credentials"] == "[REDACTED]"
    assert finding["credentialData"] == "[REDACTED]"
    assert finding["apiKey"] == "[REDACTED]"


@pytest.mark.parametrize(
    "field_name",
    (
        "apiKeys",
        "api_keys",
        "apiKeyValue",
        "api_key_value",
        "privateKeys",
        "private_keys",
        "privateKeyData",
        "private_key_pem",
        "accessKeyId",
        "access_key_id",
        "passwords",
    ),
)
def test_normalize_finding_redacts_plural_sensitive_fields(field_name):
    finding = normalize_finding(
        {
            "rule_id": "external-finding-42",
            "category": "misconfig",
            field_name: ["opaque-production-credential"],
        }
    )

    assert finding[field_name] == "[REDACTED]"


def test_normalize_finding_redacts_multiline_quoted_assignment():
    finding = normalize_finding(
        {
            "rule_id": "external-finding-42",
            "category": "misconfig",
            "message": "password='first-secret-line\nsecond-secret-line'",
        }
    )

    assert finding["message"] == "password=[REDACTED]"


@pytest.mark.parametrize("delimiter", ("'''", '\"\"\"', "`"))
def test_normalize_finding_redacts_multiline_delimited_assignment(delimiter):
    message = (
        f"private_key = {delimiter}-----BEGIN PRIVATE KEY-----\n"
        f"OPAQUEKEYBODY\n-----END PRIVATE KEY-----{delimiter}"
    )

    finding = normalize_finding({"message": message})

    assert finding["message"] == "private_key = [REDACTED]"


@pytest.mark.parametrize(
    "message",
    (
        r'password="""first-secret\""" second-secret"""',
        r"password='''first-secret\''' second-secret'''",
    ),
)
def test_normalize_finding_honors_escaped_triple_quote(message):
    finding = normalize_finding({"message": message})

    assert finding["message"] == "password=[REDACTED]"


@pytest.mark.parametrize("scope", ("proj", "svcacct"))
def test_normalize_finding_redacts_scoped_provider_token(scope):
    token = f"sk-{scope}-" + "a" * 24

    finding = normalize_finding({"message": f"Observed {token}"})

    assert token not in finding["message"]


def test_normalize_finding_validates_line_without_late_string_coercion():
    finding = normalize_finding({"line": SecretLine()})

    assert finding["line"] == 1
    assert "late-coercion-secret" not in repr(finding)


@pytest.mark.parametrize(
    ("raw_line", "expected"),
    (("7", 7), ("0", 1), ("9" * 21, 1), ("seven", 1), (True, 1)),
)
def test_normalize_finding_validates_line_number(raw_line, expected):
    assert normalize_finding({"line": raw_line})["line"] == expected


def test_normalize_finding_preserves_values_when_secret_keys_collide():
    first_token = "ghp_" + "a" * 24
    second_token = "ghp_" + "b" * 24
    third_token = "ghp_" + "c" * 24

    finding = normalize_finding(
        {
            "rule_id": "external-finding-42",
            "category": "misconfig",
            "provider_metadata": {
                first_token: "first nonsecret value",
                second_token: "second nonsecret value",
                third_token: "third nonsecret value",
            },
        }
    )

    assert finding["provider_metadata"] == {
        "[REDACTED]": "first nonsecret value",
        "[REDACTED]#2": "second nonsecret value",
        "[REDACTED]#3": "third nonsecret value",
    }


def test_normalize_finding_redacts_text_introduced_by_coercion():
    finding = normalize_finding(
        {
            "rule_id": "external-finding-42",
            "category": "misconfig",
            "message": SecretText(),
        }
    )

    assert "coerced-secret-value" not in finding["message"]


def test_safe_report_snippet_bounds_text_before_pattern_scanning(monkeypatch):
    observed_bounds = []

    def record_bounds(text, *, visible_length):
        observed_bounds.append((len(text), visible_length))
        return text[:visible_length]

    monkeypatch.setattr(
        "appguardrail_core.findings.redact_sensitive_prefix", record_bounds
    )

    safe_report_snippet("x" * 10_000, max_len=20)

    assert observed_bounds == [(148, 20)]


def test_safe_report_snippet_redacts_token_crossing_truncation_boundary():
    token = "ghp_" + "a" * 24
    snippet = "x" * 380 + " " + token

    rendered = safe_report_snippet(snippet, max_len=400)

    assert "ghp_" not in rendered
    assert token not in rendered
    assert rendered.endswith("\n...[truncated]")


def test_safe_report_snippet_never_pulls_lookahead_into_output():
    token = "ghp_" + "a" * 24
    opaque_tail = "opaque-value-beyond-cutoff"
    snippet = token + " " + "x" * (400 - len(token) - 1) + opaque_tail

    rendered = safe_report_snippet(snippet, max_len=400)

    assert opaque_tail not in rendered
    assert "opaque-value" not in rendered
    assert rendered.endswith("\n...[truncated]")


def test_safe_report_snippet_merges_overlapping_secret_spans():
    token = "ghp_" + "a" * 24
    snippet = f"Authorization: Bearer {token}" + "x" * 500

    rendered = safe_report_snippet(snippet, max_len=40)

    assert rendered == "Authorization: [REDACTED]\n...[truncated]"


def test_nonsecret_provider_rules_preserve_benign_evidence():
    for rule_id in (
        "github-actions-mutable-branch-writer",
        "stripe-price-from-client",
        "aws-public-bucket",
        "google-oauth-redirect",
        "insecure-random-security-token",
    ):
        finding = normalize_finding(
            {
                "rule_id": rule_id,
                "category": "misconfig",
                "snippet": "benign configuration evidence",
            }
        )

        assert finding["snippet"] == "benign configuration evidence"


@pytest.mark.parametrize(
    "rule_id",
    (
        "external-api-token-exposure",
        "credential-leak",
        "password-disclosure",
        "private-key-checked-in",
        "jwt-exposure",
    ),
)
def test_sensitive_rule_semantics_suppress_opaque_snippet(rule_id):
    finding = normalize_finding(
        {
            "rule_id": rule_id,
            "category": "misconfig",
            "snippet": "opaque-value-without-known-provider-format",
        }
    )

    assert finding["snippet"] == "[REDACTED: sensitive match suppressed]"
