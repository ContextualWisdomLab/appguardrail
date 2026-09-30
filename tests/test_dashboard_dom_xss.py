import pytest
import os
import json
import re
from playwright.sync_api import sync_playwright
from scanner.cli.appguardrail import make_dashboard_server

def _serve(server):
    import threading
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

def test_hostile_severity_rendering_in_browser(tmp_path):
    # 1. Create a dummy finding with a hostile severity value
    findings_json = tmp_path / "findings.json"
    findings_json.write_text(
        json.dumps(
            {
                "schema": "appguardrail.findings.v1",
                "findings": [
                    {
                        "rule_id": "hostile-rule",
                        "severity": "__proto__",
                        "message": "Hostile finding",
                        "file": "dummy.py",
                        "line": 1,
                        "remediation": "",
                        "verification": "",
                        "context": "app-code"
                    }
                ]
            }
        )
    )

    # 2. Start the dashboard server serving console.html
    html_content = (os.path.join(os.path.dirname(__file__), "..", "scanner", "dashboard", "console.html"))
    with open(html_content, 'rb') as f:
         content = f.read()

    # Passing the finding JSON as the single scan
    server = make_dashboard_server("127.0.0.1", 0, content, findings_json)
    port = server.server_address[1]

    _serve(server)

    # 3. Use Playwright to verify rendering
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(f"http://127.0.0.1:{port}/")

            # Since console.html takes an API key, we might need to simulate local data or intercept
            # For simplicity, we can intercept the API call console.html makes
            page.route("**/api/v1/scans", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps({"scans": [{"id": "1", "created_at": "now", "repo": "test", "total": 1}]})
            ))

            page.route("**/api/v1/scans/1", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps({"id": "1", "created_at": "now", "findings": [{"rule_id": "rule1", "severity": "__proto__", "message": "msg", "file": "f", "line": 1}]})
            ))

            # Simulate API Key entry to load data if required, or just trigger load
            # console.html uses sessionStorage.getItem("ag_key") or expects an API key input.
            page.evaluate("KEY = 'test'; load();")

            page.wait_for_selector("tr.scan")
            page.click("tr.scan")

            page.wait_for_selector("#detail table tbody tr")

            chip_bg_color = page.evaluate("() => { const chip = document.querySelector('#detail table tbody tr td span.pill'); return chip ? chip.style.background : null; }")
            assert chip_bg_color is not None
            assert 'var(--info)' in chip_bg_color

            chip_text = page.evaluate("() => { const chip = document.querySelector('#detail table tbody tr td span.pill'); return chip ? chip.textContent : null; }")
            assert chip_text == "__proto__"

            assert page.evaluate("() => Object.prototype.color === undefined")
            browser.close()
    finally:
        server.shutdown()
