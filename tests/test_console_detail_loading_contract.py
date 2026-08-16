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


def test_console_keeps_org_api_key_ephemeral_and_requests_viewer_scope():
    """The read-only console must not persist an owner-capable bearer key."""
    html = _console_html()

    assert "sessionStorage" not in html
    assert 'placeholder="Viewer API key (agk_…)"' in html
    assert "viewer-scoped" in html
    assert 'let KEY="";' in html
    assert '$("#logout").onclick=()=>{KEY="";location.reload();};' in html


def test_console_connection_state_is_exception_safe_and_single_flight():
    """Connection cleanup and input edits must not permit overlapping loads."""
    html = _console_html()

    assert "let connecting=false;" in html
    assert "function syncConnectState(){" in html
    assert 'button.disabled=connecting||!$("#key").value.trim();' in html
    assert 'button.setAttribute("aria-busy","true");' in html
    assert 'button.removeAttribute("aria-busy");' in html
    assert "async function connect(){" in html
    assert "if(connecting)return;" in html
    assert "try{" in html
    assert "const connected=await load();" in html
    assert 'if(!connected)KEY="";' in html
    assert "}finally{" in html
    assert '$("#key").addEventListener("input",syncConnectState);' in html
    assert "if(KEY)load()" not in html
    assert "syncConnectState();" in html


def test_console_escapes_scan_identifiers_in_attribute_context():
    """Untrusted scan identifiers must not break out of the data-id attribute."""
    html = _console_html()

    assert 'data-id="${esc(s.id)}"' in html
    assert 'data-id="${s.id}"' not in html


def test_console_close_buttons_explain_the_escape_shortcut():
    """Both success and error close controls must expose their keyboard shortcut."""
    html = _console_html()

    assert html.count('aria-label="Close details" title="Close (Esc)"') == 2


def test_console_detail_close_control_is_wired_and_focused_on_every_result() -> None:
    """Success and error detail paths must focus their actionable close control."""
    html = _console_html()
    success_path = html.split('const s=await api("/api/v1/scans/"+id);', 1)[1].split(
        "}catch(e){", 1
    )[0]
    error_path = html.split("}catch(e){", 1)[1].split("}finally{", 1)[0]

    for result_path in (success_path, error_path):
        assert 'class="close-btn" aria-label="Close details"' in result_path
        assert (
            'd.querySelector(".close-btn").addEventListener("click",closeDetail);'
            in result_path
        )
        assert (
            'd.querySelector(".close-btn").focus({preventScroll:true});' in result_path
        )
        assert "d.focus({preventScroll:true});" not in result_path


def test_console_hover_feedback_excludes_disabled_controls():
    """Hover feedback must not imply that a disabled control can be activated."""
    html = _console_html()

    assert "button:hover:not(:disabled)" in html
    assert "transition:filter 0.2s, opacity 0.2s" in html
