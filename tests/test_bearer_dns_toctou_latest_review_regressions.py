"""Current-head regressions for the bearer DNS TOCTOU detector family."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_PRIMARY = "python-bearer-preflight-dns-toctou"
_MUTATION = "python-bearer-preflight-dns-toctou-header-mutation"
_FAMILY = {_PRIMARY, _MUTATION}


def _scan_source(tmp_path: Path, source: str):
    source_file = tmp_path / "push.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] in _FAMILY
    ]


def test_packaged_detector_subrules_have_unique_stable_ids():
    loaded = [rule["id"] for rule in SCAN_RULES if rule["id"] in _FAMILY]
    assert loaded.count(_PRIMARY) == 1
    assert loaded.count(_MUTATION) == 1


def test_post_request_with_data_and_method_before_headers_is_detected(tmp_path):
    source = """\
def deliver(url, payload, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    return urllib.request.urlopen(req, timeout=5)
"""
    findings = _scan_source(tmp_path, source)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == _PRIMARY


def test_nested_fixed_destination_bearer_replacement_breaks_provenance(tmp_path):
    source = """\
def deliver(url, api_key, use_fixed):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    if use_fixed:
        req = urllib.request.Request(
            "https://fixed.example/api/v1/scans",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        return urllib.request.urlopen(req, timeout=5)
    return None
"""
    assert not _scan_source(tmp_path, source)


def test_nested_same_endpoint_bearer_replacement_preserves_provenance(tmp_path):
    source = """\
def deliver(url, api_key, rebuild):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
    )
    if rebuild:
        req = urllib.request.Request(
            endpoint,
            headers={"Authorization": f"Bearer {api_key}"},
        )
        return urllib.request.urlopen(req, timeout=5)
    return None
"""
    findings = _scan_source(tmp_path, source)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == _PRIMARY
