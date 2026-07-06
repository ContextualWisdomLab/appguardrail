"""Rule metadata helpers for buyer-friendly AppGuardrail findings."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

REFERENCE_RE = re.compile(r"\[(OWASP [^\]]+|CWE-\d+[^\]]*|CVE-\d{4}-\d+[^\]]*)\]")

CATEGORY_REFERENCE_DEFAULTS = {
    "authz": ("OWASP A01:2021 - Broken Access Control", "CWE-862 - Missing Authorization"),
    "dependency": ("OWASP A06:2021 - Vulnerable and Outdated Components",),
    "injection": ("OWASP A03:2021 - Injection", "CWE-74 - Injection"),
    "misconfig": ("OWASP A05:2021 - Security Misconfiguration",),
    "payment": ("OWASP A08:2021 - Software and Data Integrity Failures",),
    "secrets": (
        "OWASP A07:2021 - Identification and Authentication Failures",
        "CWE-798 - Use of Hard-coded Credentials",
    ),
    "storage": ("OWASP A01:2021 - Broken Access Control",),
}

SAMM_BY_CATEGORY = {
    "authz": "Implementation / Secure Build",
    "dependency": "Implementation / Secure Build",
    "injection": "Implementation / Secure Build",
    "misconfig": "Operations / Environment Management",
    "payment": "Verification / Requirements-driven Testing",
    "secrets": "Operations / Environment Management",
    "storage": "Implementation / Secure Build",
}

REMEDIATION_BY_CATEGORY = {
    "authz": (
        "Require authentication and server-side authorization before returning "
        "or mutating user-owned data."
    ),
    "dependency": (
        "Upgrade the affected package or document a time-bound risk acceptance "
        "when no fix exists."
    ),
    "injection": (
        "Replace string-built execution or query paths with parameterized APIs "
        "and strict allowlists."
    ),
    "misconfig": (
        "Restore the secure default or document the production boundary that "
        "makes the exception safe."
    ),
    "payment": (
        "Validate payment events and prices server-side using provider "
        "signatures and trusted product data."
    ),
    "secrets": (
        "Remove the secret from source, rotate it, and load future values from "
        "managed secret storage."
    ),
    "storage": "Enforce storage or database access controls with authenticated ownership policies.",
}


@dataclass(frozen=True)
class RuleMetadata:
    """Normalized rule metadata shared by CLI, reports, and future UI."""

    rule_id: str
    severity: str
    category: str
    source: str
    references: tuple[str, ...]
    owasp: tuple[str, ...]
    cwe: tuple[str, ...]
    samm_practice: str
    remediation: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "source": self.source,
            "references": self.references,
            "owasp": self.owasp,
            "cwe": self.cwe,
            "samm_practice": self.samm_practice,
            "remediation": self.remediation,
        }


def extract_public_references(message: str) -> tuple[str, ...]:
    """Extract OWASP, CWE, and CVE references already embedded in rule copy."""
    # ⚡ Bolt: O(N) deduplication using dict.fromkeys instead of O(N^2) list membership check
    references = (
        " ".join(match.group(1).split())
        for match in REFERENCE_RE.finditer(message or "")
    )
    return tuple(dict.fromkeys(references))


def build_rule_metadata(
    rule_id: str,
    severity: str,
    message: str,
    *,
    category: str,
    source: str = "appguardrail-rule",
) -> RuleMetadata:
    """Build a stable metadata envelope for a scanner finding."""
    references = _merge_references(
        extract_public_references(message),
        CATEGORY_REFERENCE_DEFAULTS.get(category, ()),
    )
    return RuleMetadata(
        rule_id=rule_id,
        severity=severity,
        category=category,
        source=source,
        references=references,
        owasp=tuple(ref for ref in references if ref.startswith("OWASP ")),
        cwe=tuple(ref for ref in references if ref.startswith("CWE-")),
        samm_practice=SAMM_BY_CATEGORY.get(category, "Verification / Security Testing"),
        remediation=REMEDIATION_BY_CATEGORY.get(
            category,
            "Review the finding, fix the unsafe pattern, and rerun AppGuardrail.",
        ),
    )


def validate_rule_metadata(metadata: RuleMetadata | dict[str, Any]) -> list[str]:
    """Return missing-field errors for rule metadata before it reaches reports."""
    data = metadata.as_dict() if isinstance(metadata, RuleMetadata) else metadata
    errors = []
    for field in ("rule_id", "severity", "category", "references", "remediation"):
        if not data.get(field):
            errors.append(f"missing {field}")
    if not data.get("owasp") and not data.get("cwe"):
        errors.append("missing public taxonomy reference")
    return errors


def _merge_references(*groups: tuple[str, ...]) -> tuple[str, ...]:
    # ⚡ Bolt: O(N) deduplication using dict.fromkeys instead of O(N^2) list membership check
    merged = (reference for group in groups for reference in group if reference)
    return tuple(dict.fromkeys(merged))
