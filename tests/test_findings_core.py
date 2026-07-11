from appguardrail_core.findings import (finding_sort_key, is_deploy_blocking,
                                        normalize_finding, normalize_findings,
                                        safe_report_snippet, severity_counts)


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
