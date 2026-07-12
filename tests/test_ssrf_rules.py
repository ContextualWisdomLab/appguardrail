"""Regression coverage for Strix/Sentinel-derived SSRF rule patterns."""

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_SSRF_RULE_IDS = {
    "python-request-input-ssrf",
    "node-request-input-ssrf",
    "python-scheme-only-ssrf-validation",
    "python-ipv4-only-ssrf-validation",
    "python-unvalidated-redirect-ssrf",
}

_BY_ID = {}
for _rule in SCAN_RULES:
    if _rule["id"] in _SSRF_RULE_IDS:
        _BY_ID.setdefault(_rule["id"], []).append(_rule)


def _matches(rule_id, text):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return any(rule["pattern"].search(text) for rule in _BY_ID[rule_id])


def _severity(rule_id):
    severities = {rule["severity"] for rule in _BY_ID[rule_id]}
    assert len(severities) == 1
    return severities.pop()


def test_python_request_input_reaches_network_sink():
    assert _matches(
        "python-request-input-ssrf",
        'return requests.get(request.args.get("url"), timeout=5)\n',
    )
    assert _matches(
        "python-request-input-ssrf",
        'return urllib.request.urlopen(req.query_params["target"], timeout=5)\n',
    )
    assert not _matches(
        "python-request-input-ssrf",
        'return requests.get("https://api.example.test/health", timeout=5)\n',
    )
    assert _severity("python-request-input-ssrf") == "CRITICAL"


def test_node_request_input_reaches_network_sink():
    assert _matches("node-request-input-ssrf", "return fetch(req.query.url);\n")
    assert _matches(
        "node-request-input-ssrf", "return axios.get(request.body.webhook);\n"
    )
    assert not _matches(
        "node-request-input-ssrf", "return fetch('https://api.example.test');\n"
    )
    assert _severity("node-request-input-ssrf") == "CRITICAL"


def test_scheme_only_guard_does_not_count_as_ssrf_destination_validation():
    unsafe = """
parsed = urllib.parse.urlparse(target_url)
if parsed.scheme not in {"http", "https"}:
    raise ValueError("unsupported scheme")
return urllib.request.urlopen(target_url, timeout=5)
"""
    safe = """
parsed = urllib.parse.urlparse(target_url)
if parsed.scheme not in {"http", "https"}:
    raise ValueError("unsupported scheme")
for result in socket.getaddrinfo(parsed.hostname, None):
    address = ipaddress.ip_address(result[4][0])
    if not address.is_global:
        raise ValueError("unsafe destination")
return urllib.request.urlopen(target_url, timeout=5)
"""
    assert _matches("python-scheme-only-ssrf-validation", unsafe)
    assert not _matches("python-scheme-only-ssrf-validation", safe)
    assert _severity("python-scheme-only-ssrf-validation") == "HIGH"


def test_ipv4_only_resolver_in_url_guard_is_detected():
    unsafe = """
def _is_safe_url(url):
    hostname = urllib.parse.urlparse(url).hostname
    resolved = socket.gethostbyname(hostname)
    return not ipaddress.ip_address(resolved).is_private
"""
    safe = """
def _is_safe_url(url):
    hostname = urllib.parse.urlparse(url).hostname
    addresses = socket.getaddrinfo(hostname, None)
    return all(ipaddress.ip_address(row[4][0]).is_global for row in addresses)
"""
    assert _matches("python-ipv4-only-ssrf-validation", unsafe)
    assert not _matches("python-ipv4-only-ssrf-validation", safe)
    assert _severity("python-ipv4-only-ssrf-validation") == "HIGH"


def test_redirect_location_requires_revalidation_before_fetch():
    unsafe = """
location = response.headers.get("Location")
return urllib.request.urlopen(location, timeout=10)
"""
    safe = """
location = response.headers.get("Location")
_validate_log_download_url(location)
return urllib.request.urlopen(location, timeout=10)
"""
    assert _matches("python-unvalidated-redirect-ssrf", unsafe)
    assert not _matches("python-unvalidated-redirect-ssrf", safe)
    assert _severity("python-unvalidated-redirect-ssrf") == "HIGH"


def test_scan_file_emits_ssrf_finding_through_runtime_path(tmp_path):
    vulnerable = tmp_path / "webhook.py"
    vulnerable.write_text(
        'return requests.get(request.args.get("callback"), timeout=5)\n',
        encoding="utf-8",
    )

    findings = _scan_file(vulnerable, tmp_path)
    finding = next(
        item for item in findings if item["rule_id"] == "python-request-input-ssrf"
    )

    assert finding["severity"] == "CRITICAL"
    assert finding["context"] == "app-code"
    assert "CWE-918" in finding["references"]
