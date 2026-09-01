"""Regression coverage for multiline Bearer DNS-TOCTOU syntax."""

from pathlib import Path

from scanner.cli.appguardrail import _scan_file

_PRIMARY = "python-bearer-preflight-dns-toctou"
_MUTATION = "python-bearer-preflight-dns-toctou-header-mutation"
_MULTILINE_CONSTRUCTOR = "python-bearer-preflight-dns-toctou-multiline-constructor"
_MULTILINE_MUTATION = "python-bearer-preflight-dns-toctou-multiline-header-mutation"
_FAMILY = {_PRIMARY, _MUTATION, _MULTILINE_CONSTRUCTOR, _MULTILINE_MUTATION}


def _family_ids(tmp_path: Path, source: str) -> list[str]:
    source_file = tmp_path / "push.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding["rule_id"]
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] in _FAMILY
    ]


def _prefix() -> str:
    return """\
def deliver(url, api_key):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
"""


def test_wrapped_constructor_bearer_value_is_detected_once(tmp_path):
    source = _prefix() + """\
    req = urllib.request.Request(endpoint, headers={"Authorization": (
        f"Bearer {api_key}"
    )})
    return urllib.request.urlopen(req)
"""
    assert _family_ids(tmp_path, source) == [_MULTILINE_CONSTRUCTOR]


def test_multiline_request_headers_value_is_detected_once(tmp_path):
    source = _prefix() + """\
    req = urllib.request.Request(
        endpoint,
        headers={
            "Authorization": (
                f"Bearer {api_key}"
            ),
        },
    )
    return urllib.request.urlopen(req)
"""
    assert _family_ids(tmp_path, source) == [_MULTILINE_CONSTRUCTOR]


def test_multiline_add_header_is_detected_once(tmp_path):
    source = _prefix() + """\
    req = urllib.request.Request(endpoint)
    req.add_header(
        "Authorization",
        f"Bearer {api_key}",
    )
    return urllib.request.urlopen(req)
"""
    assert _family_ids(tmp_path, source) == [_MULTILINE_MUTATION]


def test_multiline_add_unredirected_header_is_detected_once(tmp_path):
    source = _prefix() + """\
    req = urllib.request.Request(endpoint)
    req.add_unredirected_header(
        "Authorization",
        f"Bearer {api_key}",
    )
    return urllib.request.urlopen(req)
"""
    assert _family_ids(tmp_path, source) == [_MULTILINE_MUTATION]


def test_multiline_direct_header_assignment_is_detected_once(tmp_path):
    source = _prefix() + """\
    req = urllib.request.Request(endpoint)
    req.headers[
        "Authorization"
    ] = (
        f"Bearer {api_key}"
    )
    return urllib.request.urlopen(req)
"""
    assert _family_ids(tmp_path, source) == [_MULTILINE_MUTATION]


def test_nested_body_headers_are_not_constructor_credentials(tmp_path):
    source = _prefix() + """\
    req = urllib.request.Request(
        endpoint,
        data=encode(headers={
            "Authorization": (
                f"Bearer {api_key}"
            )
        }),
    )
    return urllib.request.urlopen(req)
"""
    assert not _family_ids(tmp_path, source)


def test_commented_bearer_value_does_not_authenticate_multiline_mutation(tmp_path):
    source = _prefix() + """\
    req = urllib.request.Request(endpoint)
    req.add_header(
        "Authorization",
        # f"Bearer {api_key}"
        "Basic fixed",
    )
    return urllib.request.urlopen(req)
"""
    assert not _family_ids(tmp_path, source)
