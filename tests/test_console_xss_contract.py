"""Regression contracts for untrusted control-plane values in the console DOM."""

from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import shutil
import subprocess
import threading

import pytest

from scanner.cli.appguardrail import dashboard_index_path


def _console_html() -> str:
    """Return the standalone control-plane console document as UTF-8 text."""
    return dashboard_index_path().with_name("console.html").read_text(encoding="utf-8")


def _browser_executable() -> str | None:
    """Return an installed Chromium-family executable for the runtime contract."""
    for candidate in (
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
    ):
        executable = shutil.which(candidate)
        if executable:
            return executable
    return None


class _QuietHandler(SimpleHTTPRequestHandler):
    """Serve the temporary browser fixture without polluting pytest output."""

    def log_message(self, _format: str, *_args: object) -> None:
        """Suppress request logs for the local-only browser fixture."""


def test_console_escapes_summary_and_history_values_before_inner_html() -> None:
    """Keep every untrusted summary/history interpolation behind ``esc``."""
    html = _console_html()

    required_escaped_fragments = {
        '${esc(l)}',
        '${esc(n)}',
        'style="background:${color}">${esc(n)}</span>',
        'data-id="${esc(s.id)}"',
        '<td>${esc(s.total)}</td>',
        '${esc(s.created_at)}',
        '${esc(String(s.deploy_blocking||0))}',
        '${esc(s.repo||"—")}',
        '${esc((s.commit||"—").slice(0,10))}',
        '${esc(f.severity)}',
        '${esc(f.rule_id)}',
        '${esc((f.message||"").split("\\n")[0].slice(0,120))}',
        '${esc(f.file)}:${esc(f.line)}',
    }
    for fragment in required_escaped_fragments:
        assert fragment in html

    required_safe_derived_fragments = {
        'pill(s.deploy_blocking,"var(--crit)")',
        'pill(s.new_blocking,"var(--high)")',
        "SEV[f.severity]||'var(--info)'",
    }
    for fragment in required_safe_derived_fragments:
        assert fragment in html

    forbidden_raw_fragments = {
        '<div class="l">${l}</div>',
        '<div class="n">${n}</div>',
        'style="background:${color}">${n}</span>',
        'data-id="${s.id}"',
        '<td>${s.total}</td>',
    }
    for fragment in forbidden_raw_fragments:
        assert fragment not in html


def test_console_executes_hostile_scan_payloads_without_dom_xss(
    tmp_path: Path,
) -> None:
    """Render hostile summary, trend, history, and detail values in Chromium."""
    browser = _browser_executable()
    if browser is None:
        if os.environ.get("CI"):
            pytest.fail("GitHub CI must provide Chrome or Chromium for the DOM XSS gate")
        pytest.skip("Chrome or Chromium is not installed")

    attack = (
        '<img src="x" onerror="document.documentElement.dataset.xssExecuted=' 
        "'1'\">"
    )
    harness = f"""
const attack={attack!r};
const scan={{
  id:attack,
  created_at:attack,
  repo:attack,
  commit:attack,
  total:attack,
  deploy_blocking:attack,
  new_blocking:attack,
  severity_counts:{{CRITICAL:attack}},
}};
window.addEventListener("error",event=>{{
  if(event.error)document.documentElement.dataset.runtimeError="1";
}});
window.fetch=async path=>({{
  status:200,
  ok:true,
  json:async()=>String(path).includes("/api/v1/scans/")
    ? {{...scan,findings:[{{severity:attack,rule_id:attack,message:attack,file:attack,line:attack}}]}}
    : {{scans:[scan]}},
}});
KEY="agk_runtime_contract";
Promise.resolve()
  .then(load)
  .then(()=>detail(scan.id,document.querySelector("tr.scan")))
  .then(()=>new Promise(resolve=>setTimeout(resolve,250)))
  .then(()=>{{document.documentElement.dataset.testComplete="1";}})
  .catch(()=>{{document.documentElement.dataset.runtimeError="1";}});
"""
    fixture = _console_html().replace("if(KEY)load();", harness)
    assert fixture != _console_html()
    fixture_path = tmp_path / "console-xss-runtime.html"
    fixture_path.write_text(fixture, encoding="utf-8")

    handler = partial(_QuietHandler, directory=str(tmp_path))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/{fixture_path.name}"
        process = subprocess.run(
            [
                browser,
                "--headless=new",
                "--disable-background-networking",
                "--disable-default-apps",
                "--disable-dev-shm-usage",
                "--disable-extensions",
                "--disable-gpu",
                "--disable-sync",
                "--metrics-recording-only",
                "--no-first-run",
                "--no-proxy-server",
                "--no-sandbox",
                "--virtual-time-budget=3000",
                "--dump-dom",
                url,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert process.returncode == 0, process.stderr
    rendered = process.stdout
    assert 'data-test-complete="1"' in rendered
    assert "data-xss-executed" not in rendered
    assert "data-runtime-error" not in rendered
    assert '<img src="x"' not in rendered
    assert "&lt;img" in rendered


def test_console_xss_regression_does_not_commit_runtime_report_fixture() -> None:
    """Keep generated findings out of the standard repository report path."""
    repository_root = Path(__file__).resolve().parents[1]

    assert not (repository_root / "reports" / "findings.json").exists()
