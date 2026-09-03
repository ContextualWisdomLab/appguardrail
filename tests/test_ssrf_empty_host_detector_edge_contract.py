"""Executable edge contracts for the empty-host SSRF detector grammar."""

from pathlib import Path

from scanner.cli.appguardrail import _scan_file

_RULE_ID = "python-ssrf-empty-host-fail-open"


def _scan_source(tmp_path: Path, source: str):
    """Run the production scanner and return only empty-host SSRF findings."""
    source_file = tmp_path / "validator.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_multiline_definition_and_annotated_host_assignment_are_detected(tmp_path):
    source = '''\
def is_safe_url(
    url: str,
    enforce: bool = True,
) -> bool:
    parsed = urllib.parse.urlparse(url)
    host: str = (parsed.hostname or "").lower()
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror:
        logger.warning("resolver unavailable")
    return True
'''
    assert len(_scan_source(tmp_path, source)) == 1


def test_nonnumeric_truthy_success_return_is_detected(tmp_path):
    source = '''\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror:
        pass
    return "allowed"
'''
    assert len(_scan_source(tmp_path, source)) == 1


def test_logical_truthy_success_return_is_detected(tmp_path):
    source = '''\
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror:
        pass
    return 0 or True
'''
    assert len(_scan_source(tmp_path, source)) == 1


def test_conditional_truthy_success_return_is_detected(tmp_path):
    source = '''\
def is_safe_url(url, reject):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror:
        pass
    return 0 if reject else True
'''
    assert len(_scan_source(tmp_path, source)) == 1
