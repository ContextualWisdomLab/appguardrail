"""Regression boundaries for restored Bearer credentials after DNS preflight."""

from pathlib import Path

from scanner.cli.appguardrail import _scan_file

_RULE_ID = "python-bearer-preflight-dns-toctou"


def _scan_source(tmp_path: Path, source: str):
    source_file = tmp_path / "push.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_remove_then_add_header_restores_bearer_path(tmp_path):
    source = """\
def deliver(url, api_key, rotate):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    if rotate:
        req.remove_header("Authorization")
        req.add_header("Authorization", f"Bearer {api_key}")
        return urllib.request.urlopen(req, timeout=5)
    return None
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_pop_then_header_assignment_restores_bearer_path(tmp_path):
    source = """\
def deliver(url, api_key, rotate):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    if rotate:
        req.headers.pop("Authorization", None)
        req.headers["Authorization"] = "Bearer " + api_key
        return urllib.request.urlopen(req, timeout=5)
    return None
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_remove_without_restoration_stays_non_credentialed(tmp_path):
    source = """\
def deliver(url, api_key, disable):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    if disable:
        req.remove_header("Authorization")
        return urllib.request.urlopen(req, timeout=5)
    return None
"""
    assert not _scan_source(tmp_path, source)


def test_restoring_non_bearer_authorization_does_not_recreate_rule_path(tmp_path):
    source = """\
def deliver(url, api_key, rotate):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    if rotate:
        req.remove_header("Authorization")
        req.add_header("Authorization", "Basic fixed")
        return urllib.request.urlopen(req, timeout=5)
    return None
"""
    assert not _scan_source(tmp_path, source)
