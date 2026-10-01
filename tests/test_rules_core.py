from appguardrail_core.rules import (build_rule_metadata,
                                     extract_public_references,
                                     validate_rule_metadata)


def test_extract_public_references_fast_path_without_brackets():
    """Skip regex work when rule copy has no bracketed public taxonomy IDs.

    Production findings often say "Hardcoded API credential detected." with no
    ``[CWE-…]`` / ``[OWASP …]`` / ``[CVE-…]`` markers. Those messages must stay
    empty so reports do not invent references, and unbracketed IDs in reviewer
    notes must stay ignored until someone wraps them in the public form.
    """
    assert extract_public_references("") == ()
    assert extract_public_references(
        "See CWE-79 and OWASP A01:2021 and CVE-2024-1234"
    ) == ()
    assert extract_public_references("[not a ref]") == ()


def test_extract_public_references_keeps_bracketed_cve_from_advisory_copy():
    """Keep a real CVE token from advisory-style rule copy for the buyer report."""
    assert extract_public_references(
        "Upgrade before exploit. [CVE-2024-12345 - Demo advisory]"
    ) == ("CVE-2024-12345 - Demo advisory",)


def test_extract_public_references_from_rule_message():
    message = (
        "Disable TLS verify false. [CWE-295 - Improper Certificate Validation] "
        "This also maps to [OWASP A05:2021 - Security Misconfiguration]."
    )

    assert extract_public_references(message) == (
        "CWE-295 - Improper Certificate Validation",
        "OWASP A05:2021 - Security Misconfiguration",
    )


def test_extract_public_references_deduplicates_in_first_seen_order():
    message = (
        "[CWE-295 - Improper Certificate Validation] appears first. "
        "[OWASP A05:2021 - Security Misconfiguration] appears second. "
        "[CWE-295 - Improper Certificate Validation] appears again."
    )

    assert extract_public_references(message) == (
        "CWE-295 - Improper Certificate Validation",
        "OWASP A05:2021 - Security Misconfiguration",
    )


def test_build_rule_metadata_adds_defaults_for_category():
    metadata = build_rule_metadata(
        "hardcoded-api-credential",
        "CRITICAL",
        "Hardcoded API credential detected.",
        category="secrets",
    )

    assert metadata.owasp == (
        "OWASP A07:2021 - Identification and Authentication Failures",
    )
    assert metadata.cwe == ("CWE-798 - Use of Hard-coded Credentials",)
    assert metadata.samm_practice == "Operations / Environment Management"
    assert "rotate" in metadata.remediation.lower()
    assert validate_rule_metadata(metadata) == []


def test_build_rule_metadata_deduplicates_message_and_default_references():
    metadata = build_rule_metadata(
        "explicit-secret",
        "HIGH",
        (
            "Hardcoded credential. "
            "[OWASP A07:2021 - Identification and Authentication Failures]"
        ),
        category="secrets",
    )

    assert metadata.references == (
        "OWASP A07:2021 - Identification and Authentication Failures",
        "CWE-798 - Use of Hard-coded Credentials",
    )
    assert metadata.owasp == (
        "OWASP A07:2021 - Identification and Authentication Failures",
    )


def test_build_rule_metadata_classifies_owasp_and_cwe_exclusively():
    """Split one reference list into OWASP vs CWE without double-counting.

    A published ID cannot start with both ``OWASP `` and ``CWE-``. The
    exclusive branch must still keep CVE tokens on ``references`` so advisory
    copy remains visible even when it is not an OWASP or CWE row.
    """
    metadata = build_rule_metadata(
        "ssrf-open-redirect",
        "HIGH",
        (
            "Validate the callback. "
            "[OWASP A10:2021 - Server-Side Request Forgery] "
            "[CWE-918 - Server-Side Request Forgery] "
            "[CVE-2024-12345 - Demo advisory]"
        ),
        category="ssrf",
    )

    assert metadata.owasp == ("OWASP A10:2021 - Server-Side Request Forgery",)
    assert metadata.cwe == ("CWE-918 - Server-Side Request Forgery",)
    assert "CVE-2024-12345 - Demo advisory" in metadata.references
    assert all(not item.startswith("CVE-") for item in metadata.owasp)
    assert all(not item.startswith("CVE-") for item in metadata.cwe)
    assert validate_rule_metadata(metadata) == []


def test_validate_rule_metadata_reports_missing_public_reference():
    errors = validate_rule_metadata(
        {
            "rule_id": "demo",
            "severity": "HIGH",
            "category": "demo",
            "references": [],
            "remediation": "Fix it.",
        }
    )

    assert "missing references" in errors
    assert "missing public taxonomy reference" in errors
