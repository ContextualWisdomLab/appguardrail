"""Regression boundaries for Bearer credentials added after DNS preflight."""

from pathlib import Path

from scanner.cli.appguardrail import _scan_file

_RULE_IDS = {
    "python-bearer-preflight-dns-toctou",
    "python-bearer-preflight-dns-toctou-header-mutation",
}


def _scan_source(tmp_path: Path, source: str):
    source_file = tmp_path / "push.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] in _RULE_IDS
    ]


def test_direct_add_header_creates_bearer_path(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint, data=b"{}")
    req.add_header("Authorization", f"Bearer {api_key}")
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _scan_source(tmp_path, source)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "python-bearer-preflight-dns-toctou-header-mutation"


def test_direct_header_assignment_creates_bearer_path(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
    req.headers["Authorization"] = "Bearer " + api_key
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _scan_source(tmp_path, source)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "python-bearer-preflight-dns-toctou-header-mutation"


def test_direct_non_bearer_header_does_not_create_path(tmp_path):
    source = """\
def deliver(url):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint)
    req.add_header("Authorization", "Basic fixed")
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


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


def test_remove_then_restore_with_reviewed_opener_is_detected(tmp_path):
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
        opener = urllib.request.build_opener(SafeRedirectHandler())
        return opener.open(req, timeout=5)
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


def test_endpoint_replacement_before_request_breaks_validated_destination(tmp_path):
    source = """\
def deliver(url, api_key, rotate):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    endpoint = "https://fixed.example/api/v1/scans"
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
    assert not _scan_source(tmp_path, source)


def test_request_replacement_before_restored_dispatch_breaks_bearer_path(tmp_path):
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
        req = urllib.request.Request("https://fixed.example/api/v1/scans")
        return urllib.request.urlopen(req, timeout=5)
    return None
"""
    assert not _scan_source(tmp_path, source)


def test_unconditional_return_before_restored_dispatch_is_not_reachable(tmp_path):
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
        return None
        return urllib.request.urlopen(req, timeout=5)
    return None
"""
    assert not _scan_source(tmp_path, source)


def test_self_derived_endpoint_before_request_retains_vulnerable_flow(tmp_path):
    source = """\
def deliver(url, api_key, rotate):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/")
    endpoint = endpoint + "/api/v1/scans"
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


def test_late_bearer_restore_is_the_actual_credential_source(tmp_path):
    source = """\
def deliver(url, api_key, rotate):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(endpoint, data=b"{}")
    if rotate:
        req.remove_header("Authorization")
        req.add_header("Authorization", f"Bearer {api_key}")
        return urllib.request.urlopen(req, timeout=5)
    return None
"""
    assert len(_scan_source(tmp_path, source)) == 1
