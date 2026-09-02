"""Verify the trusted OpenCode-to-contextual-orchestrator CI handoff.

This is a control-plane handshake, not model inference. It checks the exact
OpenCode CLI version selected by the workflow, validates that the exported
gateway URL is loopback-only, loads the ephemeral bearer from the sidecar's
restricted file, and performs one authenticated ``GET /v1/models`` request.
No provider credential enters this process.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import stat
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence


_MAX_TOKEN_BYTES = 4096
_MAX_CATALOG_BYTES = 1024 * 1024
_CONTROL_PLANE_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class HandoffEvidence:
    """Record non-secret evidence produced by one successful handoff check."""

    observed_version: str
    endpoint: str
    model_count: int


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject redirects so the loopback bearer can never follow a remote Location."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        """Decline every redirect; urllib converts the response into an HTTP error."""
        del req, fp, code, msg, headers, newurl
        return None


def _normalized_version(output: str) -> str:
    """Normalize the two version strings emitted by supported OpenCode builds."""
    value = output.strip()
    if value.startswith("opencode "):
        value = value.removeprefix("opencode ").strip()
    return value


def _models_endpoint(base_url: str) -> str:
    """Return a loopback-only model-catalog endpoint without credential ambiguity."""
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError("contextual-orchestrator gateway must use a loopback HTTP URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("contextual-orchestrator gateway URL must not contain credentials")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ValueError("contextual-orchestrator gateway host must be a numeric loopback address") from exc
    if not address.is_loopback:
        raise ValueError("contextual-orchestrator gateway host must be loopback")
    if parsed.query or parsed.fragment:
        raise ValueError("contextual-orchestrator gateway URL must not contain query or fragment data")
    base_path = parsed.path.rstrip("/")
    if base_path not in ("", "/v1"):
        raise ValueError("contextual-orchestrator gateway base path must be empty or /v1")
    path = "/v1/models"
    netloc = f"[{parsed.hostname}]:{parsed.port}" if address.version == 6 and parsed.port else parsed.netloc
    return urllib.parse.urlunsplit(("http", netloc, path, "", ""))


def _read_bearer_file(path: Path) -> str:
    """Read the sidecar bearer only from the runner-owned mode-600 regular file."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("gateway bearer file must be a regular, non-symlink file")
    metadata = path.stat()
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise ValueError("gateway bearer file must be owned by the current runner user")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError("gateway bearer file must have mode 600")
    payload = path.read_bytes()
    if not 1 <= len(payload) <= _MAX_TOKEN_BYTES:
        raise ValueError("gateway bearer must contain between 1 and 4096 bytes")
    if b"\r" in payload or b"\n" in payload:
        raise ValueError("gateway bearer must not contain CR or LF")
    return payload.decode("utf-8")


def _observed_opencode_version(opencode: Path) -> str:
    """Execute only the pinned CLI version command and return its normalized value."""
    completed = subprocess.run(
        [os.fspath(opencode), "--version"],
        check=True,
        capture_output=True,
        text=True,
    )
    return _normalized_version(completed.stdout)


def _fetch_model_catalog(endpoint: str, token: str) -> dict[str, object]:
    """Fetch one bounded authenticated loopback catalog without following redirects."""
    request = urllib.request.Request(
        endpoint,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=_CONTROL_PLANE_TIMEOUT_SECONDS) as response:
            content_type = response.headers.get_content_type()
            if content_type != "application/json":
                raise RuntimeError("gateway model catalog must return application/json")
            payload = response.read(_MAX_CATALOG_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"gateway model catalog returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError("gateway model catalog transport failed") from exc
    if len(payload) > _MAX_CATALOG_BYTES:
        raise RuntimeError("gateway model catalog exceeded the 1 MiB control-plane bound")
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("gateway model catalog was not valid UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("gateway model catalog must be a JSON object")
    return parsed


def verify_handoff(
    *,
    opencode: Path,
    expected_version: str,
    base_url: str,
    token: str,
) -> HandoffEvidence:
    """Verify CLI identity and the authenticated loopback model-catalog contract."""
    observed_version = _observed_opencode_version(opencode)
    if observed_version != expected_version:
        raise RuntimeError(
            f"OpenCode version {observed_version!r} does not match reviewed {expected_version!r}"
        )
    endpoint = _models_endpoint(base_url)
    catalog = _fetch_model_catalog(endpoint, token)
    models = catalog.get("data")
    if not isinstance(models, list) or not models:
        raise RuntimeError("gateway model catalog must contain at least one model row")
    for row in models:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"].strip():
            raise RuntimeError("gateway model catalog contains an invalid model row")
    return HandoffEvidence(
        observed_version=observed_version,
        endpoint=endpoint,
        model_count=len(models),
    )


def _parser() -> argparse.ArgumentParser:
    """Build the narrow CI command-line contract."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--opencode", required=True, type=Path)
    parser.add_argument("--expected-version", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Consume sidecar exports and print only non-secret handoff evidence."""
    args = _parser().parse_args(argv)
    base_url = os.environ.get("CONTEXTUAL_ORCHESTRATOR_BASE_URL", "")
    token_file = os.environ.get("CONTEXTUAL_ORCHESTRATOR_TOKEN_FILE", "")
    if not base_url:
        raise SystemExit("CONTEXTUAL_ORCHESTRATOR_BASE_URL is required")
    if not token_file:
        raise SystemExit("CONTEXTUAL_ORCHESTRATOR_TOKEN_FILE is required")
    evidence = verify_handoff(
        opencode=args.opencode,
        expected_version=args.expected_version,
        base_url=base_url,
        token=_read_bearer_file(Path(token_file)),
    )
    print(json.dumps(asdict(evidence), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
