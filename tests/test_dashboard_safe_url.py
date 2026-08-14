"""Security regressions for dashboard reference URL normalization."""

import re

from scanner.cli.appguardrail import dashboard_index_path


def _safe_url_body() -> str:
    """Return the shipped dashboard ``safeUrl`` helper body."""
    html = dashboard_index_path().read_text(encoding="utf-8")
    match = re.search(
        r"function safeUrl\(u\)\{(?P<body>.*?)\n\}",
        html,
        flags=re.DOTALL,
    )
    assert match is not None, "dashboard safeUrl helper is missing"
    return match.group("body")


def test_dashboard_safe_url_canonicalizes_before_rendering_href() -> None:
    """Approved HTTP(S) references must render the parser's canonical URL."""
    body = _safe_url_body()

    assert "typeof u !== 'string'" in body
    assert "const candidate = u.trim();" in body
    assert "const parsed = new URL(candidate, window.location.href);" in body
    assert "return parsed.href;" in body
    assert "return u;" not in body


def test_dashboard_safe_url_rejects_scheme_relative_reference_variants() -> None:
    """Scheme-relative slash or backslash forms stay fail-closed after trimming."""
    body = _safe_url_body()

    assert "if (/^[\\\\/]{2}/.test(candidate)) return '#';" in body
