#!/usr/bin/env python3
"""Apply the bounded scanner and package integration for issue 892 exactly once."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _replace_once(text: str, old: str, new: str, label: str) -> str:
    """Replace one reviewed fragment and fail when the branch shape is unexpected."""
    occurrences = text.count(old)
    if occurrences != 1:
        raise RuntimeError(f"{label}: expected one occurrence, found {occurrences}")
    return text.replace(old, new, 1)


def _patch_scanner() -> None:
    """Route bearer-authenticated scan uploads through the pinned HTTPS module."""
    path = ROOT / "scanner" / "cli" / "appguardrail.py"
    text = path.read_text(encoding="utf-8")
    import_anchor = "from appguardrail_core.controlplane import SafeRedirectHandler\n"
    import_block = (
        import_anchor
        + "from appguardrail_core.pinned_https import (\n"
        + "    DestinationValidationError,\n"
        + "    PinnedHTTPSFailure,\n"
        + "    post_json_pinned_https,\n"
        + ")\n"
    )
    text = _replace_once(text, import_anchor, import_block, "scanner import")

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
    except ValueError:
        parsed = None
    if parsed is None or parsed.scheme.lower() != "https" or not parsed.hostname:
        _console_print(
            f"⚠️  --push URL must be a public HTTPS URL, got {url}",
            file=sys.stderr,
        )
        return

    payload = {
        "findings": list(normalize_findings(findings)),
        "repo": os.environ.get("GITHUB_REPOSITORY"),
        "commit": os.environ.get("GITHUB_SHA"),
    }
    endpoint = url.rstrip("/") + "/api/v1/scans"
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
            f"⚠️  --push URL must be a public HTTPS URL, got {url}",
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
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
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
    drift = body.get("new_blocking")
    extra = f", {drift} newly deploy-blocking" if drift else ""
    _console_print(f"📡 Pushed scan #{body.get('id')} to control plane{extra}.")
'''
    text = text[:start] + replacement + "\n" + text[end:]
    path.write_text(text, encoding="utf-8")


def _patch_core_exports() -> None:
    """Expose the reusable transport through the package-level MSA boundary."""
    path = ROOT / "appguardrail_core" / "__init__.py"
    text = path.read_text(encoding="utf-8")
    anchor = "from appguardrail_core.openssf_report import augment_buyer_diligence_report\n"
    block = (
        anchor
        + "from appguardrail_core.pinned_https import (\n"
        + "    DestinationValidationError,\n"
        + "    HTTPSDestination,\n"
        + "    PinnedHTTPSConnection,\n"
        + "    PinnedHTTPSFailure,\n"
        + "    PinnedHTTPSResponse,\n"
        + "    ResolvedAddress,\n"
        + "    post_json_pinned_https,\n"
        + "    resolve_public_https_destination,\n"
        + ")\n"
    )
    text = _replace_once(text, anchor, block, "core import")
    additions = {
        '    "DriftAssessment",\n': '    "DestinationValidationError",\n    "DriftAssessment",\n',
        '    "MAX_RETENTION_DAYS",\n': '    "HTTPSDestination",\n    "MAX_RETENTION_DAYS",\n',
        '    "PullRequestGateSummary",\n': (
            '    "PinnedHTTPSConnection",\n'
            '    "PinnedHTTPSFailure",\n'
            '    "PinnedHTTPSResponse",\n'
            '    "PullRequestGateSummary",\n'
        ),
        '    "ReportContext",\n': '    "ReportContext",\n    "ResolvedAddress",\n',
        '    "parse_openssf_project_matches",\n': (
            '    "parse_openssf_project_matches",\n'
            '    "post_json_pinned_https",\n'
        ),
        '    "render_org_readiness_report",\n': (
            '    "render_org_readiness_report",\n'
            '    "resolve_public_https_destination",\n'
        ),
    }
    for old, new in additions.items():
        text = _replace_once(text, old, new, f"core export {old.strip()}")
    path.write_text(text, encoding="utf-8")


def _patch_existing_ssrf_contract() -> None:
    """Update the legacy CLI assertion to the stricter bearer transport wording."""
    path = ROOT / "tests" / "test_ssrf_protection.py"
    text = path.read_text(encoding="utf-8")
    text = _replace_once(
        text,
        '"URL must be a valid http/https URL and not point to internal infrastructure"',
        '"URL must be a public HTTPS URL"',
        "legacy CLI error contract",
    )
    path.write_text(text, encoding="utf-8")


def main() -> int:
    """Apply every reviewed integration patch without broad repository mutation."""
    _patch_scanner()
    _patch_core_exports()
    _patch_existing_ssrf_contract()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
