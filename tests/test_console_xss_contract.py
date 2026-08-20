"""Regression contracts for untrusted control-plane values in the console DOM."""

from pathlib import Path

from scanner.cli.appguardrail import dashboard_index_path


def _console_html() -> str:
    """Return the standalone control-plane console document as UTF-8 text."""
    return dashboard_index_path().with_name("console.html").read_text(encoding="utf-8")


def test_console_escapes_summary_history_and_pill_values_before_inner_html() -> None:
    """Keep every untrusted summary/history interpolation behind ``esc``."""
    html = _console_html()

    required_escaped_fragments = {
        '${esc(l)}',
        '${esc(n)}',
        'data-id="${esc(s.id)}"',
        '<td>${esc(s.total)}</td>',
        '${esc(s.created_at)}',
        '${esc(s.repo||"—")}',
        '${esc((s.commit||"—").slice(0,10))}',
        'function pill(n,color){return n>0?`<span class="pill" '
        'style="background:${color}">${esc(n)}</span>`:',
    }
    for fragment in required_escaped_fragments:
        assert fragment in html

    forbidden_raw_fragments = {
        '<div class="l">${l}</div>',
        '<div class="n">${n}</div>',
        'data-id="${s.id}"',
        '<td>${s.total}</td>',
        'style="background:${color}">${n}</span>`',
    }
    for fragment in forbidden_raw_fragments:
        assert fragment not in html


def test_console_xss_regression_does_not_commit_runtime_report_fixture() -> None:
    """Keep generated findings out of the standard repository report path."""
    repository_root = Path(__file__).resolve().parents[1]

    assert not (repository_root / "reports" / "findings.json").exists()
