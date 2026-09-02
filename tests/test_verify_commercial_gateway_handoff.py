"""Executable tests for the commercial builder CLI-to-gateway handoff boundary."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "ci" / "verify_commercial_gateway_handoff.py"


def _load_module():
    """Load the handoff verifier only after asserting the production boundary exists."""
    assert MODULE_PATH.exists(), "commercial gateway handoff verifier is missing"
    spec = importlib.util.spec_from_file_location(
        "verify_commercial_gateway_handoff",
        MODULE_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _GatewayHandler(BaseHTTPRequestHandler):
    """Serve one authenticated OpenAI-compatible model-catalog response."""

    token = "gateway-test-token"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        """Return the model catalog only for the expected bearer and endpoint."""
        if self.path != "/v1/models":
            self.send_response(404)
            self.end_headers()
            return
        if self.headers.get("Authorization") != f"Bearer {self.token}":
            self.send_response(401)
            self.end_headers()
            return
        payload = json.dumps(
            {"object": "list", "data": [{"id": "orchestrator/free", "object": "model"}]}
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: object) -> None:
        """Keep test output deterministic by suppressing the fixture access log."""


def _fake_opencode(tmp_path: Path, version: str = "1.18.13") -> Path:
    """Create a minimal executable implementing the pinned CLI version contract."""
    executable = tmp_path / "opencode"
    executable.write_text(
        "#!/bin/sh\n"
        "if [ \"${1:-}\" = \"--version\" ]; then\n"
        f"  printf '%s\\n' '{version}'\n"
        "  exit 0\n"
        "fi\n"
        "exit 64\n",
        encoding="utf-8",
    )
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    return executable


def test_verify_handoff_exercises_pinned_cli_and_authenticated_gateway(tmp_path: Path) -> None:
    """The verifier couples CLI identity, loopback routing, bearer auth, and API shape."""
    module = _load_module()
    executable = _fake_opencode(tmp_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _GatewayHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        result = module.verify_handoff(
            opencode=executable,
            expected_version="1.18.13",
            base_url=base_url,
            token=_GatewayHandler.token,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result.model_count == 1
    assert result.observed_version == "1.18.13"
    assert result.endpoint.endswith("/v1/models")


def test_verify_handoff_rejects_non_loopback_gateway_before_network(tmp_path: Path) -> None:
    """A compromised export cannot redirect the bearer to a remote origin."""
    module = _load_module()
    executable = _fake_opencode(tmp_path)

    with pytest.raises(ValueError, match="loopback"):
        module.verify_handoff(
            opencode=executable,
            expected_version="1.18.13",
            base_url="https://attacker.invalid",
            token="sensitive-token",
        )


def test_verify_handoff_rejects_cli_version_drift(tmp_path: Path) -> None:
    """The executable contract fails before gateway traffic when the CLI pin drifts."""
    module = _load_module()
    executable = _fake_opencode(tmp_path, version="1.18.14")

    with pytest.raises(RuntimeError, match="OpenCode version"):
        module.verify_handoff(
            opencode=executable,
            expected_version="1.18.13",
            base_url="http://127.0.0.1:18080",
            token="gateway-test-token",
        )


def test_main_reads_sidecar_exports_without_exposing_bearer(monkeypatch, tmp_path: Path, capsys) -> None:
    """The CLI entry point consumes sidecar exports and emits only non-secret evidence."""
    module = _load_module()
    executable = _fake_opencode(tmp_path)
    token_file = tmp_path / "bearer.token"
    token_file.write_text(_GatewayHandler.token, encoding="utf-8")
    token_file.chmod(0o600)
    observed: dict[str, str] = {}

    def fake_verify_handoff(*, opencode, expected_version, base_url, token):
        observed.update(
            opencode=str(opencode),
            expected_version=expected_version,
            base_url=base_url,
            token=token,
        )
        return module.HandoffEvidence(
            observed_version="1.18.13",
            endpoint="http://127.0.0.1:18080/v1/models",
            model_count=3,
        )

    monkeypatch.setattr(module, "verify_handoff", fake_verify_handoff)
    monkeypatch.setenv("CONTEXTUAL_ORCHESTRATOR_BASE_URL", "http://127.0.0.1:18080")
    monkeypatch.setenv("CONTEXTUAL_ORCHESTRATOR_TOKEN_FILE", str(token_file))

    assert module.main(["--opencode", str(executable), "--expected-version", "1.18.13"]) == 0
    rendered = capsys.readouterr().out
    assert json.loads(rendered)["model_count"] == 3
    assert _GatewayHandler.token not in rendered
    assert observed["token"] == _GatewayHandler.token
    assert os.fspath(executable) == observed["opencode"]
