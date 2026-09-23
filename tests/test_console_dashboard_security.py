"""Security contracts for the standalone control-plane console."""

from pathlib import Path


CONSOLE_PATH = (
    Path(__file__).resolve().parents[1] / "scanner" / "dashboard" / "console.html"
)


def test_trend_accessibility_attributes_escape_blocking_count() -> None:
    """API-provided counts must not become raw innerHTML attribute text."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")
    trend_template = html.split('$("#trend").innerHTML=', 1)[1].split(
        '$("#history tbody").innerHTML=', 1
    )[0]

    assert "${s.deploy_blocking||0}" not in trend_template
    assert trend_template.count("${esc(String(Number(s.deploy_blocking)||0))}") >= 2


def test_history_scalar_fields_are_constrained_before_innerhtml_interpolation() -> None:
    """History rows must not interpolate raw API identifiers or numeric fields."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")
    history_template = html.split('$("#history tbody").innerHTML=', 1)[1].split(
        'document.querySelectorAll("tr.scan")', 1
    )[0]

    assert 'data-id="${s.id}"' not in history_template
    assert 'data-id="${esc(s.id)}"' in history_template
    assert "<td>${s.total}</td>" not in history_template
    assert "${pill(s.deploy_blocking" not in history_template
    assert "${pill(s.new_blocking" not in history_template
    assert "<td>${Number(s.total)||0}</td>" in history_template
    assert '${pill(Number(s.deploy_blocking)||0,"var(--crit)")}' in history_template
    assert '${pill(Number(s.new_blocking)||0,"var(--high)")}' in history_template


def test_console_escape_helper_covers_html_text_and_attribute_metacharacters() -> None:
    """String interpolation uses one helper that escapes text and quoted attributes."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")

    assert 'replace(/[&<>"\']/g' in html
    for entity in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;"):
        assert entity in html


def test_detail_panel_close_invalidates_async_work_and_restores_focus() -> None:
    """Close controls must prevent stale detail responses from stealing focus."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")

    assert "function closeDetail()" in html
    assert "currentDetailRequest+=1;" in html
    assert "lastDetailFocus instanceof HTMLElement && lastDetailFocus.isConnected" in html
    assert 'e.key==="Escape"' in html
    assert html.count('class="close-btn" aria-label="Close details"') == 2
    assert html.count('d.querySelector(".close-btn").addEventListener("click",closeDetail);') == 2
    assert html.count("d.focus({preventScroll:true});") == 2
    assert 'aria-label="${esc(s.created_at)}: ${esc(String(Number(s.deploy_blocking)||0))} blocking"' in html
