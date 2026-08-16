"""Security contracts for the standalone control-plane console."""

from pathlib import Path


CONSOLE_PATH = (
    Path(__file__).resolve().parents[1] / "scanner" / "dashboard" / "console.html"
)


def test_trend_accessibility_attributes_escape_blocking_count() -> None:
    """Untrusted scan counts must not escape innerHTML attribute values."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")
    trend_template = html.split('$("#trend").innerHTML=', 1)[1].split(
        '$("#history tbody").innerHTML=', 1
    )[0]

    assert "${s.deploy_blocking||0}" not in trend_template
    assert trend_template.count("${esc(String(s.deploy_blocking||0))}") >= 2


def test_scan_summary_and_pills_escape_untrusted_api_scalars() -> None:
    """API-provided counts must be escaped before they reach innerHTML."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")
    pill_function = html.split("function pill(n,color){", 1)[1].split(
        "function scrollDetailIntoView", 1
    )[0]
    stats_template = html.split('$("#stats").innerHTML=', 1)[1].split(
        "const ord=", 1
    )[0]

    assert ">${n}</span>" not in pill_function
    assert ">${esc(n)}</span>" in pill_function
    assert '<div class="n">${n}</div>' not in stats_template
    assert '<div class="n">${esc(n)}</div>' in stats_template


def test_scan_history_escapes_untrusted_api_id_and_total() -> None:
    """Scan identity and totals must not break HTML text or attribute contexts."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")
    history_template = html.split('$("#history tbody").innerHTML=', 1)[1].split(
        'document.querySelectorAll("tr.scan")', 1
    )[0]

    assert 'data-id="${s.id}"' not in history_template
    assert 'data-id="${esc(s.id)}"' in history_template
    assert "<td>${s.total}</td>" not in history_template
    assert "<td>${esc(s.total)}</td>" in history_template


def test_detail_panel_close_invalidates_async_work_and_restores_focus() -> None:
    """Close controls must prevent stale detail responses from stealing focus."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")

    assert "function closeDetail()" in html
    assert "currentDetailRequest+=1;" in html
    assert "lastDetailFocus instanceof HTMLElement && lastDetailFocus.isConnected" in html
    assert 'e.key==="Escape"' in html
    assert html.count('class="close-btn" aria-label="Close details"') == 2
    assert html.count('d.querySelector(".close-btn").addEventListener("click",closeDetail);') == 2
    assert html.count("d.querySelector(\".close-btn\").focus({preventScroll:true});") == 2
    assert 'aria-label="${esc(s.created_at)}: ${esc(String(s.deploy_blocking||0))} blocking"' in html
