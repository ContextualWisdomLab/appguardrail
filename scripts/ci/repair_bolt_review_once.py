"""Apply the bounded review fixes for PR #877 and then remove this script."""

from __future__ import annotations

from pathlib import Path


def _replace_once(text: str, old: str, new: str, label: str) -> str:
    """Replace one exact reviewed contract or fail without partial output."""
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label} contract changed: expected one match, found {count}")
    return text.replace(old, new, 1)


def _repair_language_paths() -> None:
    """Preserve string-subclass compatibility in the language hot path."""
    path = Path("appguardrail_core/language.py")
    text = path.read_text(encoding="utf-8")
    text = _replace_once(
        text,
        """        # ⚡ Bolt: Use type(file_path) instead of isinstance for faster check
        if type(file_path) is not str:
""",
        """        # Preserve the public str | Path contract, including str subclasses.
        if not isinstance(file_path, str):
""",
        "language path type",
    )
    path.write_text(text, encoding="utf-8")


def _repair_scanner() -> None:
    """Hoist scan-root metadata safely and require HTTPS for bearer uploads."""
    path = Path("scanner/cli/appguardrail.py")
    text = path.read_text(encoding="utf-8")
    text = _replace_once(
        text,
        """    # ⚡ Bolt: Use type(path) is not str instead of isinstance for faster check
    return path.as_posix() if type(path) is not str else path.replace("\\\\", "/")
""",
        """    return path.replace("\\\\", "/") if isinstance(path, str) else path.as_posix()
""",
        "display path type",
    )
    text = _replace_once(
        text,
        """    if scan_path.is_file():
        files_to_scan = [scan_path]
    else:
        files_to_scan = _collect_files(scan_path)

    resolved_base_path = scan_path if scan_path.is_dir() else Path(".").resolve()
    resolved_base_path_str = str(resolved_base_path)
    resolved_base_path_prefix = (
        resolved_base_path_str + os.sep
        if not resolved_base_path_str.endswith(os.sep)
        else resolved_base_path_str
    )
""",
        """    scan_path_is_file = scan_path.is_file()
    if scan_path_is_file:
        files_to_scan = [scan_path]
    else:
        files_to_scan = _collect_files(scan_path)

    resolved_base_path = Path(".").resolve() if scan_path_is_file else scan_path
    resolved_base_path_str = str(resolved_base_path)
    resolved_base_path_prefix = (
        resolved_base_path_str + os.sep
        if not resolved_base_path_str.endswith(os.sep)
        else resolved_base_path_str
    )
""",
        "cmd_scan path context",
    )
    text = _replace_once(
        text,
        """            resolved_base_path_prefix,
        )
""",
        """            resolved_base_path_prefix,
            scan_path_is_file,
        )
""",
        "scan_file call",
    )
    text = _replace_once(
        text,
        """    resolved_base_path: Path = None,
    resolved_base_path_str: str = None,
    resolved_base_path_prefix: str = None,
):
""",
        """    resolved_base_path: Path | None = None,
    resolved_base_path_str: str | None = None,
    resolved_base_path_prefix: str | None = None,
    base_path_is_file: bool | None = None,
):
""",
        "scan_file signature",
    )
    text = _replace_once(
        text,
        """    # ⚡ Bolt: Hoist expensive relative_to base_path resolution outside of loops.
    # We now compute resolved base path in the main loop to avoid stat calls entirely for each file.
    if resolved_base_path is None:
        resolved_base_path = base_path if base_path.is_dir() else Path(".").resolve()
        resolved_base_path_str = str(resolved_base_path)
        resolved_base_path_prefix = (
            resolved_base_path_str + os.sep
            if not resolved_base_path_str.endswith(os.sep)
            else resolved_base_path_str
        )
""",
        """    # Callers scanning many files precompute this immutable path context once.
    if base_path_is_file is None:
        base_path_is_file = base_path.is_file()
    if resolved_base_path is None:
        resolved_base_path = Path(".").resolve() if base_path_is_file else base_path
    if resolved_base_path_str is None:
        resolved_base_path_str = str(resolved_base_path)
    if resolved_base_path_prefix is None:
        resolved_base_path_prefix = (
            resolved_base_path_str + os.sep
            if not resolved_base_path_str.endswith(os.sep)
            else resolved_base_path_str
        )
""",
        "scan_file fallback",
    )
    if text.count("if base_path.is_file()") != 2:
        raise SystemExit("expected two match-path base_path.is_file() calls")
    text = text.replace("if base_path.is_file()", "if base_path_is_file")
    text = _replace_once(
        text,
        """    if not _is_safe_url(url):
        _console_print(
            f"⚠️  --push URL must be a valid http/https URL and not point to internal infrastructure, got {url}",
            file=sys.stderr,
        )
        return
""",
        """    if not _is_secure_control_plane_url(url):
        _console_print(
            f"⚠️  --push URL must be a public HTTPS URL, got {url}",
            file=sys.stderr,
        )
        return
""",
        "push URL validation",
    )
    marker = "\n\ndef _push_findings(url, findings):\n"
    helper = """

def _is_secure_control_plane_url(url: str) -> bool:
    \"\"\"Return whether a bearer-token destination is public HTTPS.\"\"\"
    import urllib.parse

    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return False
    return parsed.scheme.lower() == \"https\" and _is_safe_url(url)


def _push_findings(url, findings):
"""
    text = _replace_once(text, marker, "\n" + helper, "push helper insertion")
    path.write_text(text, encoding="utf-8")


def _repair_redirects() -> None:
    """Prevent downgrade and cross-origin forwarding of sensitive headers."""
    path = Path("appguardrail_core/controlplane.py")
    text = path.read_text(encoding="utf-8")
    text = _replace_once(
        text,
        """class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _is_safe_url(newurl):
            raise urllib.error.URLError("Unsafe redirect target")
        return super().redirect_request(req, fp, code, msg, headers, newurl)
""",
        """class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    \"\"\"Reject unsafe redirects and prevent cross-origin credential forwarding.\"\"\"

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        \"\"\"Build one safe redirected request with bounded credential scope.\"\"\"
        if not _is_safe_url(newurl):
            raise urllib.error.URLError("Unsafe redirect target")

        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is None or req is None:
            return redirected

        original = urlparse(req.full_url)
        target = urlparse(newurl)
        has_sensitive_header = req.has_header("Authorization") or req.has_header(
            "Proxy-Authorization"
        )
        if not has_sensitive_header:
            return redirected
        if original.scheme.lower() != "https" or target.scheme.lower() != "https":
            raise urllib.error.URLError("Authenticated redirects require HTTPS")

        def origin(parsed):
            scheme = parsed.scheme.lower()
            port = parsed.port or (443 if scheme == "https" else 80)
            return scheme, (parsed.hostname or "").lower(), port

        try:
            cross_origin = origin(original) != origin(target)
        except ValueError as exc:
            raise urllib.error.URLError("Unsafe redirect target") from exc
        if cross_origin:
            redirected.remove_header("Authorization")
            redirected.remove_header("Proxy-Authorization")
        return redirected
""",
        "redirect handler",
    )
    path.write_text(text, encoding="utf-8")


def _repair_existing_tests() -> None:
    """Align existing SSRF assertions with the stronger HTTPS-only push contract."""
    path = Path("tests/test_ssrf_protection.py")
    text = path.read_text(encoding="utf-8")
    text = _replace_once(
        text,
        '"URL must be a valid http/https URL and not point to internal infrastructure"',
        '"public HTTPS URL"',
        "push URL error assertion",
    )
    path.write_text(text, encoding="utf-8")


def _write_tests() -> None:
    """Create behavioral regressions for every review finding."""
    Path("tests/test_bolt_review_regressions.py").write_text(
        '''"""Regression contracts for reviewed scanner hot-path and redirect changes."""

from __future__ import annotations

import inspect
import urllib.error
import urllib.request

import pytest

from appguardrail_core.controlplane import SafeRedirectHandler
from appguardrail_core.language import detect_language_axes
from scanner.cli import appguardrail as cli


class StringPath(str):
    """A string subtype accepted by public path APIs."""


def _redirect_copy(_self, request, _fp, _code, _msg, _headers, new_url):
    """Return a redirected request that initially copies every source header."""
    return urllib.request.Request(new_url, headers=dict(request.header_items()))


def test_string_subclass_uses_string_path_contract() -> None:
    """String subclasses must not be treated as pathlib objects."""
    path = StringPath(r"src\\service.py")

    assert detect_language_axes([path]) == {"python"}
    assert cli._display_path(path) == "src/service.py"


def test_push_rejects_public_http_before_network(monkeypatch, capsys) -> None:
    """Bearer credentials are never sent over a cleartext public URL."""
    monkeypatch.setenv("APPGUARDRAIL_API_KEY", "secret")

    def fail_network(*_args, **_kwargs):
        raise AssertionError("network must not be reached")

    monkeypatch.setattr(urllib.request, "build_opener", fail_network)
    cli._push_findings("http://example.com", [])

    assert "public HTTPS URL" in capsys.readouterr().err


def test_cross_origin_redirect_removes_sensitive_headers(monkeypatch) -> None:
    """A public cross-origin redirect cannot inherit bearer credentials."""
    monkeypatch.setattr(
        urllib.request.HTTPRedirectHandler, "redirect_request", _redirect_copy
    )
    request = urllib.request.Request(
        "https://api.example.com/scans",
        headers={
            "Authorization": "Bearer secret",
            "Proxy-Authorization": "Basic secret",
        },
    )

    redirected = SafeRedirectHandler().redirect_request(
        request, None, 302, "Found", {}, "https://collector.example.net/next"
    )

    assert redirected is not None
    assert redirected.get_header("Authorization") is None
    assert redirected.get_header("Proxy-Authorization") is None


def test_same_origin_https_redirect_preserves_authorization(monkeypatch) -> None:
    """A same-origin HTTPS redirect retains its scoped bearer credential."""
    monkeypatch.setattr(
        urllib.request.HTTPRedirectHandler, "redirect_request", _redirect_copy
    )
    request = urllib.request.Request(
        "https://api.example.com/scans",
        headers={"Authorization": "Bearer secret"},
    )

    redirected = SafeRedirectHandler().redirect_request(
        request, None, 302, "Found", {}, "https://api.example.com/next"
    )

    assert redirected is not None
    assert redirected.get_header("Authorization") == "Bearer secret"


def test_authenticated_redirect_rejects_https_downgrade(monkeypatch) -> None:
    """Authenticated redirects cannot downgrade transport security."""
    monkeypatch.setattr(
        urllib.request.HTTPRedirectHandler, "redirect_request", _redirect_copy
    )
    request = urllib.request.Request(
        "https://api.example.com/scans",
        headers={"Authorization": "Bearer secret"},
    )

    with pytest.raises(urllib.error.URLError, match="require HTTPS"):
        SafeRedirectHandler().redirect_request(
            request, None, 302, "Found", {}, "http://example.com/next"
        )


def test_scan_file_has_one_direct_caller_fallback_stat() -> None:
    """The root file check exists only in the standalone-call fallback."""
    source = inspect.getsource(cli._scan_file)

    assert source.count("base_path.is_file()") == 1
    assert "if base_path_is_file" in source
''',
        encoding="utf-8",
    )


def _write_docs() -> None:
    """Replace overclaims with the reviewed behavioral boundaries."""
    learning = Path(".jules/bolt.md")
    text = learning.read_text(encoding="utf-8")
    marker = "## 2026-08-05 - File scanning path stat optimization"
    prefix, separator, _tail = text.partition(marker)
    if not separator:
        raise SystemExit("Bolt learning marker missing")
    replacement = """## 2026-08-05 - File scanning path stat optimization
**Learning:** Rechecking a constant scan root for every file adds avoidable filesystem metadata calls, while standalone `_scan_file` callers still need a safe one-time fallback.
**Action:** Compute the scan-root file classification and normalized prefix once in `cmd_scan`, pass them into `_scan_file`, and let direct callers compute the same values once per call.

## 2026-08-05 - File path string operations optimization
**Learning:** Native string basename and suffix extraction avoids temporary normalized strings, but a public `str | Path` API must continue to accept `str` subclasses.
**Action:** Use `isinstance(file_path, str)` for the public contract and `rfind()` for slash and dot boundaries without allocating a replaced path string.
"""
    learning.write_text(prefix + replacement, encoding="utf-8")
    Path("CHANGELOG.d/877-scan-path-performance.md").write_text(
        """### Changed

- Reduced repeated scan-root path classification and relative-path allocation in large repository scans while preserving `str` subclass compatibility.
- Restricted bearer-authenticated control-plane uploads and redirects to HTTPS and removed sensitive headers on cross-origin redirects.
""",
        encoding="utf-8",
    )


def main() -> None:
    """Apply all reviewed fixes in a deterministic order."""
    _repair_language_paths()
    _repair_scanner()
    _repair_redirects()
    _repair_existing_tests()
    _write_tests()
    _write_docs()


if __name__ == "__main__":
    main()
