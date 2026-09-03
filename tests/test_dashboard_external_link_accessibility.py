"""Behavioral contract for dashboard external-reference link accessibility."""

from __future__ import annotations

from html.parser import HTMLParser
import json
from pathlib import Path
import subprocess

from scanner.cli.appguardrail import dashboard_index_path


class _AnchorParser(HTMLParser):
    """Capture the first rendered anchor and its visible text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.attrs: dict[str, str | None] = {}
        self.text = ""
        self._inside_anchor = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a" and not self.attrs:
            self.attrs = dict(attrs)
            self._inside_anchor = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._inside_anchor = False

    def handle_data(self, data: str) -> None:
        if self._inside_anchor:
            self.text += data


def _render_detail_html(reference: str) -> str:
    """Execute the dashboard's real ``openDetail`` renderer for one reference."""
    html = dashboard_index_path().read_text(encoding="utf-8")
    helpers = html[
        html.index("function esc(s)") : html.index("\n\nlet ALL")
    ]
    open_detail = html[
        html.index("function openDetail(f)") : html.index("\n\n// Dialog event listeners")
    ]
    node_script = f"""
const window = {{location: {{href: "https://dashboard.test/"}}}};
const detail = {{innerHTML: "", showModal() {{}}}};
const document = {{
  activeElement: null,
  getElementById(id) {{ return id === "detail" ? detail : null; }}
}};
const SEV = {{INFO: {{color: "#000"}}}};
const isDeployBlocking = () => false;
let lastFocus = null;
{helpers}
{open_detail}
openDetail({{
  severity: "INFO",
  rule_id: "TEST-001",
  file: "app.py",
  line: 1,
  category: "test",
  context: "app-code",
  message: "message",
  remediation: "fix",
  verification: "verify",
  references: [{json.dumps(reference)}],
  owasp: [],
  cwe: []
}});
process.stdout.write(detail.innerHTML);
"""
    completed = subprocess.run(
        ["node", "--input-type=module", "-e", node_script],
        check=True,
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    return completed.stdout


def test_dashboard_external_reference_links_announce_new_tab_without_losing_purpose() -> None:
    """The rendered anchor keeps its destination in both visible and accessible names."""
    reference = "https://example.test/report?id=42&view=full"
    parser = _AnchorParser()
    parser.feed(_render_detail_html(reference))

    assert parser.attrs["href"] == reference
    assert parser.attrs["target"] == "_blank"
    assert parser.attrs["rel"] == "noopener"
    assert parser.attrs["aria-label"] == f"{reference} (opens in a new tab)"
    assert parser.text == reference
