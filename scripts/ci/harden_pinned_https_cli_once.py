#!/usr/bin/env python3
"""Apply and stage the bounded CLI hardening discovered after issue 892 RED tests."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _replace_once(text: str, old: str, new: str, label: str) -> str:
    """Replace one reviewed fragment and fail on an unexpected branch shape."""
    occurrences = text.count(old)
    if occurrences != 1:
        raise RuntimeError(f"{label}: expected one occurrence, found {occurrences}")
    return text.replace(old, new, 1)


def _patch_cli() -> None:
    """Harden base URL construction and validate untrusted response receipts."""
    path = ROOT / "scanner" / "cli" / "appguardrail.py"
    text = path.read_text(encoding="utf-8")
    start = text.index("\ndef _push_findings(url, findings):")
    end = text.index("\ndef _write_sarif(findings, output_path: Path):", start)
    replacement = r'''
def _push_findings(url, findings):
    """POST normalized findings through DNS-pinned public HTTPS."""
    import urllib.parse

    api_key = os.environ.get("APPGUARDRAIL_API_KEY", "")
    if not api_key:
        _console_print(
            "⚠️  --push set but APPGUARDRAIL_API_KEY is empty; skipping push.",
            file=sys.stderr,
        )
        return
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
        parsed.port
    except (TypeError, ValueError):
        parsed = None
        hostname = None
    if (
        parsed is None
        or parsed.scheme.lower() != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or bool(parsed.query)
        or bool(parsed.fragment)
    ):
        _console_print(
            "⚠️  --push URL must be a public HTTPS URL without credentials, "
            "query, or fragment; skipping push.",
            file=sys.stderr,
        )
        return

    base_path = parsed.path.rstrip("/")
    endpoint_path = f"{base_path}/api/v1/scans" if base_path else "/api/v1/scans"
    endpoint = urllib.parse.urlunsplit(
        ("https", parsed.netloc, endpoint_path, "", "")
    )
    payload = {
        "findings": list(normalize_findings(findings)),
        "repo": os.environ.get("GITHUB_REPOSITORY"),
        "commit": os.environ.get("GITHUB_SHA"),
    }
    try:
        response = post_json_pinned_https(
            endpoint,
            payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            timeout=15,
        )
    except DestinationValidationError:
        _console_print(
            "⚠️  --push URL must be a public HTTPS URL without credentials, "
            "query, or fragment; skipping push.",
            file=sys.stderr,
        )
        return
    except PinnedHTTPSFailure:
        _console_print(
            "⚠️  Control-plane push failed; scan still completed.",
            file=sys.stderr,
        )
        return

    if not 200 <= response.status < 300:
        _console_print(
            f"⚠️  Control-plane push failed ({response.status}); scan still completed.",
            file=sys.stderr,
        )
        return
    try:
        body = json.loads(response.body or b"{}")
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        _console_print(
            "⚠️  Control-plane push returned an invalid response; scan still completed.",
            file=sys.stderr,
        )
        return
    if not isinstance(body, dict):
        _console_print(
            "⚠️  Control-plane push returned an invalid response; scan still completed.",
            file=sys.stderr,
        )
        return

    scan_id = body.get("id")
    new_blocking = body.get("new_blocking", 0)
    if (
        not isinstance(scan_id, int)
        or isinstance(scan_id, bool)
        or scan_id <= 0
        or not isinstance(new_blocking, int)
        or isinstance(new_blocking, bool)
        or new_blocking < 0
    ):
        _console_print(
            "⚠️  Control-plane push returned an invalid response; scan still completed.",
            file=sys.stderr,
        )
        return

    extra = f", {new_blocking} newly deploy-blocking" if new_blocking else ""
    _console_print(f"📡 Pushed scan #{scan_id} to control plane{extra}.")
'''
    path.write_text(text[:start] + replacement + "\n" + text[end:], encoding="utf-8")


def _patch_changelog() -> None:
    """Record the fail-closed base URL and receipt validation boundary."""
    path = ROOT / "CHANGELOG.d" / "892-pinned-control-plane-delivery.md"
    text = path.read_text(encoding="utf-8")
    anchor = (
        "- Added bounded timeout, redirect-count, response-size, JSON, and non-secret "
        "error contracts plus exact statement-coverage and operator documentation for "
        "standalone, organization-service, and naruon reuse.\n"
    )
    replacement = anchor + (
        "- Reject ambiguous control-plane base URLs and validate receipt identifiers and "
        "deploy-blocking counts before rendering terminal output, preventing query/fragment "
        "confusion and forged control-sequence messages.\n"
    )
    path.write_text(
        _replace_once(text, anchor, replacement, "changelog hardening entry"),
        encoding="utf-8",
    )


def main() -> int:
    """Apply the reviewed GREEN implementation for the current failing tests."""
    _patch_cli()
    _patch_changelog()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
