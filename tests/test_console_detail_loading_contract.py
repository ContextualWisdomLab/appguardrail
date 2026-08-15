"""Regression tests for asynchronous console detail rendering."""

from scanner.cli.appguardrail import dashboard_index_path


def _console_html() -> str:
    """Return the standalone console document as UTF-8 text."""
    return dashboard_index_path().with_name("console.html").read_text(encoding="utf-8")


def test_console_ignores_out_of_order_detail_results_and_errors():
    """Only the most recently selected scan may update the shared detail panel."""
    html = _console_html()

    assert "let currentDetailRequest=0;" in html
    assert "const requestId=++currentDetailRequest;" in html
    assert html.count("if(requestId!==currentDetailRequest)return;") == 2
    assert "tr.dataset.detailRequest=String(requestId);" in html
    assert "tr.dataset.detailRequest===String(requestId)" in html


def test_console_exposes_loading_busy_and_error_states():
    """Loading and failure states must remain perceivable to assistive technology."""
    html = _console_html()

    assert 'tr.setAttribute("aria-busy","true");' in html
    assert 'aria-live="polite" class="muted">Loading scan details...' in html
    assert 'role="alert" class="err">Error loading details:' in html
    assert 'tr.removeAttribute("aria-busy");' in html


def test_console_detail_scrolling_respects_reduced_motion():
    """Successful and failed detail requests must honor reduced-motion preferences."""
    html = _console_html()

    assert 'window.matchMedia("(prefers-reduced-motion: reduce)").matches' in html
    assert "element.scrollIntoView();" in html
    assert 'element.scrollIntoView({behavior:"smooth"});' in html
    assert html.count("scrollDetailIntoView(d);") == 2


def test_console_detail_close_control_is_wired_and_focused_on_every_result():
    """Success and error details must expose the same operable close affordance."""
    html = _console_html()
    detail_flow = html.split("async function detail(id,tr){", 1)[1].split(
        '$("#connect").onclick=', 1
    )[0]
    result_flow = detail_flow.split("try{", 1)[1]
    success_path, remainder = result_flow.split("}catch(e){", 1)
    error_path = remainder.split("}finally{", 1)[0]

    for path in (success_path, error_path):
        assert 'title="Close (Esc)"' in path
        assert 'd.querySelector(".close-btn").addEventListener("click",closeDetail);' in path
        assert 'd.querySelector(".close-btn").focus({preventScroll:true});' in path

    assert "d.focus({preventScroll:true});" not in detail_flow
