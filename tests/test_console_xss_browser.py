"""Rendered-browser regression for hostile AppGuardrail console payloads."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
from urllib.parse import urlsplit

import pytest

from scanner.cli.appguardrail import dashboard_index_path

_IMAGE_PAYLOAD = (
    '<img id="xss-image" src="/missing" '
    'onerror="document.body.dataset.xssExecuted=\'1\'">'
)
_SCRIPT_PAYLOAD = (
    '<script id="xss-script">'
    "document.body.dataset.xssExecuted='1'"
    "</script>"
)


def _instrumented_console() -> bytes:
    """Return the shipped console with deterministic test-only startup code."""
    source = (
        dashboard_index_path()
        .with_name("console.html")
        .read_text(encoding="utf-8")
    )
    startup = "if(KEY)load();"
    replacement = """(async()=>{
  KEY="agk_browser_xss_test";
  await load();
  const row=document.querySelector("tr.scan");
  if(!row){document.body.dataset.testFailure="missing-scan-row";return;}
  await detail(row.dataset.id,row);
  document.body.dataset.testDone="1";
})();"""
    assert source.count(startup) == 1
    return source.replace(startup, replacement, 1).encode("utf-8")


def _write_response(handler: BaseHTTPRequestHandler, content_type: str, body: bytes) -> None:
    """Write one bounded no-store HTTP response for the browser fixture."""
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


class _ConsoleFixtureHandler(BaseHTTPRequestHandler):
    """Serve the console and hostile list/detail API payloads on loopback."""

    console_document = b""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        """Serve one deterministic fixture response based on the request path."""
        path = urlsplit(self.path).path
        if path == "/console.html":
            _write_response(self, "text/html; charset=utf-8", self.console_document)
            return
        if path == "/api/v1/scans":
            payload = {
                "scans": [
                    {
                        "id": _IMAGE_PAYLOAD,
                        "created_at": _SCRIPT_PAYLOAD,
                        "repo": _IMAGE_PAYLOAD,
                        "commit": _SCRIPT_PAYLOAD,
                        "total": _IMAGE_PAYLOAD,
                        "deploy_blocking": 1,
                        "new_blocking": 1,
                        "severity_counts": {"CRITICAL": _IMAGE_PAYLOAD},
                    }
                ]
            }
            _write_response(
                self,
                "application/json; charset=utf-8",
                json.dumps(payload).encode("utf-8"),
            )
            return
        if path.startswith("/api/v1/scans/"):
            payload = {
                "id": _IMAGE_PAYLOAD,
                "created_at": _SCRIPT_PAYLOAD,
                "repo": _IMAGE_PAYLOAD,
                "findings": [
                    {
                        "severity": "CRITICAL",
                        "rule_id": _IMAGE_PAYLOAD,
                        "message": _SCRIPT_PAYLOAD,
                        "file": _IMAGE_PAYLOAD,
                        "line": _SCRIPT_PAYLOAD,
                    }
                ],
            }
            _write_response(
                self,
                "application/json; charset=utf-8",
                json.dumps(payload).encode("utf-8"),
            )
            return
        self.send_error(404)

    def log_message(self, _format: str, *args: object) -> None:
        """Suppress fixture request logging so test output stays deterministic."""


def _chrome_path() -> Path:
    """Return the dedicated workflow-provided Chrome binary or skip locally."""
    configured = os.environ.get("APPGUARDRAIL_CHROME_PATH")
    if not configured:
        pytest.skip("rendered-browser lane supplies APPGUARDRAIL_CHROME_PATH")
    chrome = Path(configured)
    assert chrome.is_file(), f"Chrome binary is missing: {chrome}"
    return chrome


def test_hostile_console_payloads_remain_inert_in_headless_chrome() -> None:
    """Render list and detail payloads and reject attacker-created DOM nodes."""
    chrome = _chrome_path()
    _ConsoleFixtureHandler.console_document = _instrumented_console()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ConsoleFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        with tempfile.TemporaryDirectory(prefix="appguardrail-chrome-") as profile:
            command = [
                str(chrome),
                "--headless=new",
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-default-apps",
                "--disable-extensions",
                "--disable-sync",
                "--metrics-recording-only",
                "--no-first-run",
                "--safebrowsing-disable-auto-update",
                f"--user-data-dir={profile}",
                "--virtual-time-budget=8000",
                "--dump-dom",
                f"http://127.0.0.1:{server.server_port}/console.html",
            ]
            try:
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
            except subprocess.TimeoutExpired as error:
                pytest.fail(f"headless Chrome timed out: {error}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert completed.returncode == 0, completed.stderr
    dom = completed.stdout
    assert 'data-test-done="1"' in dom
    assert "data-test-failure=" not in dom
    assert 'data-xss-executed="1"' not in dom
    assert '<img id="xss-image"' not in dom
    assert '<script id="xss-script"' not in dom
    assert "&lt;img" in dom
    assert "&lt;script" in dom
