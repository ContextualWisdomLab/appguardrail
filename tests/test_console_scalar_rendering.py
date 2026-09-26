"""Executable trust-boundary regression for dashboard scalar rendering."""

from pathlib import Path
import json
import subprocess


CONSOLE = Path(__file__).resolve().parents[1] / "scanner" / "dashboard" / "console.html"


def test_untrusted_scalar_fields_cannot_emit_markup() -> None:
    """Count and identifier payloads must render as bounded scalar text."""
    html = CONSOLE.read_text(encoding="utf-8")
    script = html.split("<script>", 1)[1].split("</script>", 1)[0]
    payload = {
        "scans": [
            {
                "id": '\"><img src=x onerror=alert(1)>',
                "created_at": "2026-09-26T00:00:00Z",
                "repo": "example/repo",
                "commit": "0123456789abcdef",
                "total": "<img src=x onerror=alert(2)>",
                "deploy_blocking": "<img src=x onerror=alert(3)>",
                "new_blocking": "Infinity",
                "severity_counts": {"CRITICAL": "-7"},
            }
        ]
    }
    harness = f"""
class HTMLElement {{}}
const elements = new Map();
function element() {{ return {{innerHTML:'', textContent:'', classList:{{add(){{}},remove(){{}},contains(){{return false;}}}}, addEventListener(){{}}}}; }}
const document = {{
  querySelector(selector) {{ if(!elements.has(selector)) elements.set(selector, element()); return elements.get(selector); }},
  querySelectorAll() {{ return []; }}, addEventListener(){{}}, activeElement:null
}};
const sessionStorage = {{getItem(){{return '';}},setItem(){{}},removeItem(){{}}}};
const window = {{matchMedia(){{return {{matches:true}};}}}};
const fetch = async () => ({{status:200, ok:true, json:async()=>({json.dumps(payload)})}});
{script}
load().then(() => console.log(JSON.stringify({{
  stats: elements.get('#stats').innerHTML,
  trend: elements.get('#trend').innerHTML,
  history: elements.get('#history tbody').innerHTML
}})));
"""
    completed = subprocess.run(
        ["node", "-e", harness], check=True, capture_output=True, text=True
    )
    rendered = json.loads(completed.stdout)

    assert "<img" not in rendered["stats"] + rendered["trend"] + rendered["history"]
    assert 'data-id="&quot;&gt;&lt;img src=x onerror=alert(1)&gt;"' in rendered["history"]
    assert '<td>0</td>' in rendered["history"]
    assert rendered["history"].count('<span class="muted">0</span>') == 2


def test_severity_color_rejects_prototype_chain_names() -> None:
    """Only own severity-map keys may select a CSS value."""
    html = CONSOLE.read_text(encoding="utf-8")
    script = html.split("<script>", 1)[1].split("</script>", 1)[0]
    selector = script[script.index("const SEV=") : script.index("\nlet KEY", script.index("const SEV="))]
    completed = subprocess.run(
        [
            "node",
            "-e",
            selector
            + "\nconsole.log(JSON.stringify(['critical','constructor','toString',null,{}].map(severityColor)));",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(completed.stdout) == [
        "var(--crit)",
        "var(--info)",
        "var(--info)",
        "var(--info)",
        "var(--info)",
    ]
