"""Static contracts for the packaged authentication-order Semgrep rules."""

from __future__ import annotations

from pathlib import Path


RULE_PATH = Path(__file__).resolve().parents[1] / "scanner" / "rules" / "authz.yml"


def _rule_block(rule_id: str) -> str:
    """Return one rule block from the small repository-owned YAML rule pack."""
    text = RULE_PATH.read_text(encoding="utf-8")
    marker = f"  - id: {rule_id}\n"
    start = text.index(marker)
    next_rule = text.find("\n  - id: ", start + len(marker))
    return text[start:] if next_rule < 0 else text[start:next_rule]


def test_missing_auth_rule_restricts_auth_and_data_symbols() -> None:
    """Arbitrary awaits cannot masquerade as authentication."""
    rule = _rule_block("missing-api-auth")

    assert "$SESSION = await $AUTH" not in rule
    assert "metavariable: $DB" in rule
    assert "regex: '^(?:db|database|prisma|repository|store|supabase)" in rule
    assert "const session = await getSession(...)" in rule
    assert "const session = await getServerSession(...)" in rule
    assert "const session = await auth(...)" in rule
    assert "const user = await requireAuth(...)" in rule
    assert "const user = await authenticate(...)" in rule
    assert "const identity = await verifySession(...)" in rule
    assert "await fetch" not in rule


def test_late_auth_rule_reports_data_access_before_authentication() -> None:
    """An approved authentication call after data access remains a finding."""
    rule = _rule_block("auth-after-data-access")

    assert "$DB.$QUERY(...)\n                ...\n                const session = await getSession(...)" in rule
    assert "$DB.$QUERY(...)\n                ...\n                const user = await requireAuth(...)" in rule
    assert "metavariable: $DB" in rule
    assert "severity: CRITICAL" in rule
