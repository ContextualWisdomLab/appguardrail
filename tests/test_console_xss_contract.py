"""Regression contracts for untrusted control-plane values in the console DOM."""

from pathlib import Path

from scanner.cli.appguardrail import dashboard_index_path


def _console_html() -> str:
    """Return the standalone control-plane console document as UTF-8 text."""
    return dashboard_index_path().with_name("console.html").read_text(encoding="utf-8")


def test_console_escapes_summary_and_history_values_before_inner_html() -> None:
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
        '${esc(n)}</span>`:`<span',
    }
    for fragment in required_escaped_fragments:
        assert fragment in html

    forbidden_raw_fragments = {
        '<div class="l">${l}</div>',
        '<div class="n">${n}</div>',
        'data-id="${s.id}"',
        '<td>${s.total}</td>',
        '>${n}</span>`:`<span',
    }
    for fragment in forbidden_raw_fragments:
        assert fragment not in html


def test_console_xss_regression_does_not_commit_runtime_report_fixture() -> None:
    """Keep generated findings out of the standard repository report path."""
    repository_root = Path(__file__).resolve().parents[1]

    assert not (repository_root / "reports" / "findings.json").exists()


def test_console_headless_xss_injection(tmp_path):
    """Prove that injecting XSS payloads into the mock API response does not create executable elements."""
    import threading
    import http.server
    import socketserver
    import json
    from playwright.sync_api import sync_playwright

    html = _console_html()
    dashboard_path = tmp_path / "console.html"
    dashboard_path.write_text(html, encoding="utf-8")

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(tmp_path), **kwargs)

        def do_GET(self):
            if self.path == '/api/v1/scans':
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "scans": [
                        {
                            "id": "<img onerror=alert('id_xss')>",
                            "repo": "test-repo",
                            "commit": "<img onerror=alert('commit_xss')>",
                            "created_at": "<img onerror=alert('date_xss')>",
                            "total": "<img onerror=alert('total_xss')>",
                            "deploy_blocking": "<img onerror=alert('block_xss')>",
                            "new_blocking": "<img onerror=alert('new_xss')>",
                            "severity_counts": {"CRITICAL": "<img onerror=alert('crit_xss')>"}
                        }
                    ]
                }).encode())
            elif self.path.startswith('/api/v1/scans/'):
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "id": "<img onerror=alert('detail_id_xss')>",
                    "created_at": "<img onerror=alert('detail_date_xss')>",
                    "repo": "<img onerror=alert('detail_repo_xss')>",
                    "findings": [
                        {
                            "rule_id": "<img onerror=alert('rule_xss')>",
                            "message": "<img onerror=alert('msg_xss')>",
                            "file": "<img onerror=alert('file_xss')>",
                            "line": "<img onerror=alert('line_xss')>",
                            "severity": "<img onerror=alert('sev_xss')>"
                        }
                    ]
                }).encode())
            else:
                super().do_GET()

    httpd = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    alerts = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                page.on("dialog", lambda dialog: alerts.append(dialog.message))

                page.goto(f"http://127.0.0.1:{port}/console.html")
                page.evaluate('sessionStorage.setItem("ag_key", "test_key")')
                page.reload()

                page.wait_for_selector("#history tbody tr.scan")

                assert len(alerts) == 0, f"XSS triggered on list view: {alerts}"

                page.click("#history tbody tr.scan")
                page.wait_for_selector("#detail table tbody tr")

                assert len(alerts) == 0, f"XSS triggered on detail view: {alerts}"

                trend_bars = page.locator("#trend .bar")
                assert trend_bars.count() == 1

                aria_label = trend_bars.first.get_attribute("aria-label")
                title = trend_bars.first.get_attribute("title")
                assert aria_label == "<img onerror=alert('date_xss')>: <img onerror=alert('block_xss')> blocking"
                assert title == "<img onerror=alert('date_xss')>: <img onerror=alert('block_xss')> blocking"
            finally:
                try:
                    browser.close()
                except Exception:
                    pass
    finally:
        try:
            httpd.shutdown()
            httpd.server_close()
        except Exception:
            pass
