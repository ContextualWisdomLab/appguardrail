"""Current-review regression boundaries for bearer DNS-validation TOCTOU detection."""

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


def test_one_line_request_body_authorization_is_not_header_evidence(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        data={"Authorization": f"Bearer {api_key}"},
    )
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_multiline_request_body_authorization_is_not_header_evidence(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        data={
            "Authorization": f"Bearer {api_key}",
        },
    )
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_fixed_request_url_cannot_borrow_endpoint_from_other_header(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        "https://fixed.example/api",
        headers={
            "Authorization": f"Bearer {api_key}",
            "X-Endpoint": endpoint,
        },
    )
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_unrelated_url_replacement_breaks_preflight_provenance(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    url = "https://fixed.example"
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    return urllib.request.urlopen(req, timeout=5)
"""
    assert not _scan_source(tmp_path, source)


def test_self_derived_validated_url_preserves_preflight_provenance(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    url = url.rstrip("/")
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    return urllib.request.urlopen(req, timeout=5)
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_nested_same_branch_header_removal_breaks_credential_path(tmp_path):
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


def test_nested_same_branch_header_pop_breaks_credential_path(tmp_path):
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
        req.headers.pop("Authorization", None)
        return urllib.request.urlopen(req, timeout=5)
    return None
"""
    assert not _scan_source(tmp_path, source)


def test_nested_same_branch_header_delete_breaks_credential_path(tmp_path):
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
        del req.headers["Authorization"]
        return urllib.request.urlopen(req, timeout=5)
    return None
"""
    assert not _scan_source(tmp_path, source)


def test_opposite_branch_header_removal_does_not_sanitize_dispatch(tmp_path):
    source = """\
def deliver(url, api_key, disable):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    if disable:
        req.remove_header("Authorization")
    else:
        return urllib.request.urlopen(req, timeout=5)
    return None
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_first_positional_request_url_still_detected(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    return urllib.request.urlopen(req, timeout=5)
"""
    assert len(_scan_source(tmp_path, source)) == 1


def test_keyword_request_url_still_detected(tmp_path):
    source = """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        url=endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    return urllib.request.urlopen(req, timeout=5)
"""
    assert len(_scan_source(tmp_path, source)) == 1
