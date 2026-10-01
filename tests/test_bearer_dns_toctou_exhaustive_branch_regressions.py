"""Control-flow regressions for exhaustive branch state in the Bearer DNS TOCTOU family."""

from pathlib import Path

from scanner.cli.appguardrail import _scan_file

_PRIMARY = "python-bearer-preflight-dns-toctou"
_FAMILY = {
    _PRIMARY,
    "python-bearer-preflight-dns-toctou-header-mutation",
    "python-bearer-preflight-dns-toctou-multiline-constructor",
    "python-bearer-preflight-dns-toctou-multiline-header-mutation",
    "python-bearer-preflight-dns-toctou-dynamic-bearer-replacement",
    "python-bearer-preflight-dns-toctou-unredirected-header-persistence",
}


def _scan_source(tmp_path: Path, source: str):
    source_file = tmp_path / "push.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] in _FAMILY
    ]


def _direct_bearer_prefix() -> str:
    return """\
def deliver(url, api_key, rotate=False, stop=False):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
"""


def test_exhaustive_if_else_authorization_removal_is_sanitized(tmp_path):
    source = _direct_bearer_prefix() + """\
    if rotate:
        req.remove_header("Authorization")
    else:
        req.remove_header("Authorization")
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_partial_authorization_removal_keeps_reachable_bearer_path(tmp_path):
    source = _direct_bearer_prefix() + """\
    if rotate:
        req.remove_header("Authorization")
    else:
        pass
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _scan_source(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_PRIMARY]


def test_exhaustive_if_else_termination_makes_following_sink_dead(tmp_path):
    source = _direct_bearer_prefix() + """\
    if stop:
        return None
    else:
        raise RuntimeError("stopped")
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_partial_termination_keeps_fallthrough_sink_reachable(tmp_path):
    source = _direct_bearer_prefix() + """\
    if stop:
        return None
    else:
        pass
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _scan_source(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_PRIMARY]
