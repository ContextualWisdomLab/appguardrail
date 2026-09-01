"""Current-head regression boundaries for Bearer DNS TOCTOU credential state."""

from pathlib import Path

from scanner.cli.appguardrail import _scan_file

_PRIMARY = "python-bearer-preflight-dns-toctou"
_MUTATION = "python-bearer-preflight-dns-toctou-header-mutation"
_FAMILY = {_PRIMARY, _MUTATION}


def _family_findings(tmp_path: Path, source: str):
    source_file = tmp_path / "push.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] in _FAMILY
    ]


def test_bearer_mutation_then_removal_is_not_credentialed_at_dispatch(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
    req.add_header("Authorization", f"Bearer {api_key}")
    req.remove_header("Authorization")
    return urllib.request.urlopen(req)
"""
    assert not _family_findings(tmp_path, source)


def test_bearer_mutation_then_non_bearer_overwrite_is_not_credentialed(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
    req.add_header("Authorization", f"Bearer {api_key}")
    req.headers["Authorization"] = "Basic fixed"
    return urllib.request.urlopen(req)
"""
    assert not _family_findings(tmp_path, source)


def test_last_bearer_mutation_after_removal_restores_vulnerable_dispatch(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
    req.add_header("Authorization", f"Bearer {api_key}")
    req.remove_header("Authorization")
    req.add_header("Authorization", f"Bearer {api_key}")
    return urllib.request.urlopen(req)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_MUTATION]


def test_keyword_urlopen_dispatch_is_detected(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
    req.add_header("Authorization", f"Bearer {api_key}")
    return urllib.request.urlopen(url=req)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_MUTATION]


def test_keyword_reviewed_opener_dispatch_is_detected(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
    req.add_header("Authorization", f"Bearer {api_key}")
    opener = urllib.request.build_opener(SafeRedirectHandler())
    return opener.open(fullurl=req)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_MUTATION]


def test_mixed_case_bearer_mutation_reaches_case_insensitive_rule(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
    req.add_header("authorization", f"bEaReR {api_key}")
    return urllib.request.urlopen(req)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_MUTATION]


def test_initial_bearer_after_post_kwargs_stays_owned_by_primary_rule(tmp_path):
    source = """\
def deliver(url, api_key, payload):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        data=payload,
        method="POST",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    req.add_header("Authorization", f"Bearer {api_key}")
    return urllib.request.urlopen(req)
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_PRIMARY]


def test_opposite_branch_removal_does_not_sanitize_bearer_dispatch_branch(tmp_path):
    source = """\
def deliver(url, api_key, refresh):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
    if refresh:
        req.remove_header("Authorization")
    else:
        req.add_header("Authorization", f"Bearer {api_key}")
        return urllib.request.urlopen(req)
    return None
"""
    findings = _family_findings(tmp_path, source)
    assert [finding["rule_id"] for finding in findings] == [_MUTATION]
