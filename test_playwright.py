from playwright.sync_api import sync_playwright
import os

def run_cuj(page):
    page.goto("file:///app/scanner/dashboard/index.html")
    page.wait_for_timeout(500)

    # Inject mock findings data
    page.evaluate("""
    const mockFindings = {
        findings: [
            {
                id: "mock-1",
                severity: "CRITICAL",
                rule_id: "sec-001",
                message: "Mock critical finding",
                file: "src/main.js",
                line: 12,
                references: ["https://example.com/sec-001"]
            }
        ]
    };
    load(mockFindings, "mock_findings.json");
    """)
    page.wait_for_timeout(500)

    # Click the finding to open details
    page.locator("tr").nth(1).click()  # Header is nth(0), so first data row is nth(1)
    page.wait_for_timeout(500)

if __name__ == "__main__":
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        run_cuj(page)
        browser.close()
        print("Playwright test completed")
