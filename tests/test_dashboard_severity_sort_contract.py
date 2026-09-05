"""Cross-surface severity ordering contract for the static dashboard."""

from appguardrail_core.findings import SEVERITIES, finding_sort_key
from scanner.cli.appguardrail import dashboard_index_path


def test_dashboard_severity_order_matches_domain_contract():
    """Dashboard ranking must use the same known and unknown order as findings.py."""
    html = dashboard_index_path().read_text(encoding="utf-8")

    assert SEVERITIES == ("CRITICAL", "HIGH", "WARNING", "INFO")
    assert "const SEV_ORDER = ['CRITICAL','HIGH','WARNING','INFO'];" in html
    assert "const SEV_ORDER_MAP = Object.fromEntries(SEV_ORDER.map((s, i) => [s, i]));" in html
    assert (
        "(SEV_ORDER_MAP[a.s] ?? 99) - (SEV_ORDER_MAP[b.s] ?? 99)"
        in html
    )

    info_rank = finding_sort_key({"severity": "INFO"})[0]
    unknown_rank = finding_sort_key({"severity": "UNRECOGNIZED"})[0]
    assert unknown_rank > info_rank
