"""Security contracts for the standalone control-plane console."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest


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
    assert 'aria-label="${esc(s.created_at)}: ${esc(String(s.deploy_blocking||0))} blocking"' in html


def test_severity_color_lookup_rejects_prototype_chain_properties() -> None:
    """Untrusted severity keys must resolve only against SEV's own properties."""
    html = CONSOLE_PATH.read_text(encoding="utf-8")

    assert "Object.prototype.hasOwnProperty.call(SEV,severity)" in html
    assert "SEV[String(f.severity||'INFO').toUpperCase()]" not in html


def test_severity_color_runtime_preserves_prototypes_and_falls_back() -> None:
    """The production selector must reject inherited and malformed keys at runtime."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the packaged console JavaScript regression")

    html = CONSOLE_PATH.read_text(encoding="utf-8")
    severity_map = re.search(r"const SEV=\{[^\n]+", html)
    selector = re.search(r"function severityColor\(value\)\{.*?\n\}", html, re.DOTALL)
    assert severity_map is not None
    assert selector is not None

    script = f"""
{severity_map.group(0)}
{selector.group(0)}
const inputs=["CRITICAL","high","WARNING","info","__proto__","constructor",
  "prototype","toString","MiXeD",null,0,{{}},[]];
const before=Reflect.ownKeys(Object.prototype);
const colors=inputs.map(severityColor);
const after=Reflect.ownKeys(Object.prototype);
console.log(JSON.stringify({{colors,prototypeUnchanged:JSON.stringify(before)===JSON.stringify(after)}}));
"""
    result = subprocess.run(
        [node, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )
    actual = json.loads(result.stdout)

    assert actual["colors"] == [
        "var(--crit)",
        "var(--high)",
        "var(--warn)",
        "var(--info)",
        *("var(--info)" for _ in range(9)),
    ]
    assert actual["prototypeUnchanged"] is True
