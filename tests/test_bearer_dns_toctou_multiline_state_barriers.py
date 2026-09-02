"""State-barrier regressions for multiline Bearer DNS-TOCTOU rules."""

from pathlib import Path

from scanner.cli.appguardrail import _scan_file

_MULTILINE_CONSTRUCTOR = "python-bearer-preflight-dns-toctou-multiline-constructor"
_MULTILINE_MUTATION = "python-bearer-preflight-dns-toctou-multiline-header-mutation"
_FAMILY = {_MULTILINE_CONSTRUCTOR, _MULTILINE_MUTATION}


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
def deliver(url, api_key, replacement=None):
    if not _is_safe_url(url):
        return None
    endpoint = url.rstrip("/") + "/api/v1/scans"
"""


def _wrapped_constructor() -> str:
    return _prefix() + """\
    req = urllib.request.Request(endpoint, headers={"Authorization": (
        f"Bearer {api_key}"
    )})
"""


def _wrapped_mutation() -> str:
    return _prefix() + """\
    req = urllib.request.Request(endpoint)
    req.add_header(
        "Authorization",
        f"Bearer {api_key}",
    )
"""


def test_multiline_constructor_headers_clear_breaks_credential_state(tmp_path):
    source = _wrapped_constructor() + """\
    req.headers.clear()
    return urllib.request.urlopen(req)
"""
    assert not _family_ids(tmp_path, source)


def test_multiline_constructor_headers_mapping_replacement_breaks_credential_state(tmp_path):
    source = _wrapped_constructor() + """\
    req.headers = {}
    return urllib.request.urlopen(req)
"""
    assert not _family_ids(tmp_path, source)


def test_multiline_constructor_opaque_authorization_replacement_breaks_credential_state(tmp_path):
    source = _wrapped_constructor() + """\
    req.headers["Authorization"] = replacement
    return urllib.request.urlopen(req)
"""
    assert not _family_ids(tmp_path, source)


def test_multiline_constructor_fixed_full_url_breaks_destination_state(tmp_path):
    source = _wrapped_constructor() + """\
    req.full_url = "https://fixed.example/api/v1/scans"
    return urllib.request.urlopen(req)
"""
    assert not _family_ids(tmp_path, source)


def test_multiline_constructor_self_derived_full_url_preserves_destination_state(tmp_path):
    source = _wrapped_constructor() + """\
    req.full_url = endpoint + "?retry=1"
    return urllib.request.urlopen(req)
"""
    assert _family_ids(tmp_path, source) == [_MULTILINE_CONSTRUCTOR]


def test_multiline_mutation_headers_clear_breaks_credential_state(tmp_path):
    source = _wrapped_mutation() + """\
    req.headers.clear()
    return urllib.request.urlopen(req)
"""
    assert not _family_ids(tmp_path, source)


def test_multiline_mutation_headers_mapping_replacement_breaks_credential_state(tmp_path):
    source = _wrapped_mutation() + """\
    req.headers = {}
    return urllib.request.urlopen(req)
"""
    assert not _family_ids(tmp_path, source)


def test_multiline_mutation_opaque_authorization_replacement_breaks_credential_state(tmp_path):
    source = _wrapped_mutation() + """\
    req.add_header("Authorization", replacement)
    return urllib.request.urlopen(req)
"""
    assert not _family_ids(tmp_path, source)


def test_multiline_mutation_fixed_full_url_breaks_destination_state(tmp_path):
    source = _wrapped_mutation() + """\
    req.full_url = "https://fixed.example/api/v1/scans"
    return urllib.request.urlopen(req)
"""
    assert not _family_ids(tmp_path, source)


def test_multiline_mutation_self_derived_full_url_preserves_destination_state(tmp_path):
    source = _wrapped_mutation() + """\
    req.full_url = endpoint + "?retry=1"
    return urllib.request.urlopen(req)
"""
    assert _family_ids(tmp_path, source) == [_MULTILINE_MUTATION]
