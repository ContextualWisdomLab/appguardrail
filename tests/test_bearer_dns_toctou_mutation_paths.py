"""Control-flow regressions for post-construction Bearer mutation paths."""

from pathlib import Path

from scanner.cli.appguardrail import _scan_file

_RULE_ID = "python-bearer-preflight-dns-toctou-header-mutation"


def _mutation_findings(tmp_path: Path, source: str):
    source_file = tmp_path / "push.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_nested_bearer_mutation_can_fall_through_to_outer_dispatch(tmp_path):
    source = """\
def deliver(url, api_key, rotate):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
    if rotate:
        req.add_header("Authorization", f"Bearer {api_key}")
    return urllib.request.urlopen(req, timeout=5)
"""
    assert len(_mutation_findings(tmp_path, source)) == 1


def test_nested_bearer_mutation_can_reach_deeper_dispatch(tmp_path):
    source = """\
def deliver(url, api_key, rotate, send):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
    if rotate:
        req.add_header("Authorization", f"Bearer {api_key}")
        if send:
            return urllib.request.urlopen(req, timeout=5)
    return None
"""
    assert len(_mutation_findings(tmp_path, source)) == 1


def test_opposite_branch_dispatch_does_not_borrow_bearer_mutation(tmp_path):
    source = """\
def deliver(url, api_key, rotate):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
    if rotate:
        req.add_header("Authorization", f"Bearer {api_key}")
    else:
        return urllib.request.urlopen(req, timeout=5)
    return None
"""
    assert _mutation_findings(tmp_path, source) == []
