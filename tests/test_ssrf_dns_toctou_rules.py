"""Regression tests for DNS validation-to-connect TOCTOU detection."""

import pytest

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "python-unauthenticated-urllib-dns-validation-to-connect"
_VULNERABLE_HEAD_SHA = "2949d30718752ea5915c7713ba227e8c19d9e5bf"
_VULNERABLE_BLOB_SHA = "576b990f13b61eda5c6b5ff3910e820498bfd923"
_FIXED_HEAD_SHA = "892a842765cb1d704ed9236ca08de494074d9551"
_FIXED_BLOB_SHA = "801e9961b9f666efb3b3e22ebfb50d5f0429e6d1"


def _rule():
    """Return the packaged DNS validation-to-connect rule."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1
    return matches[0]


def _direct_request_source():
    """Build the original validate-then-re-resolve request flow."""
    return """\
def send_alert(url, payload):
    if not _is_safe_url(url):
        return False
    request = urllib.request.Request(url, data=payload)
    opener = urllib.request.build_opener(SafeRedirectHandler())
    opener.open(request, timeout=10)
"""


def _exact_vulnerable_source():
    """Replay the verbatim protected function repaired by PR #1327."""
    return """\
def _send_alert(
    url: str,
    payload: dict[str, Any],
    *,
    org_name: "str | None" = None,
    new_findings: "list[dict[str, Any]] | None" = None,
) -> bool:
    \"\"\"Best-effort POST of a drift alert. Never raises; returns delivery success.

    For Slack Incoming Webhook URLs (host ``hooks.slack.com``) the alert is
    rendered as a Block Kit message so Slack shows a readable card; every other
    URL receives the generic JSON ``payload`` unchanged (backward compatible).
    \"\"\"
    import urllib.error
    import urllib.request

    if not _is_safe_url(url):
        return False

    if _is_slack_webhook(url):
        body = _slack_blocks(org_name, payload, new_findings or [])
    else:
        body = payload

    try:
        req = urllib.request.Request(  # noqa: S310 - Safe URL scheme validated
            url,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        opener = urllib.request.build_opener(SafeRedirectHandler())
        opener.open(  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            req, timeout=10
        )  # noqa: S310 - Safe URL scheme validated
        return True
    except (urllib.error.URLError, OSError, ValueError):
        return False
"""


def _direct_urlopen_source():
    """Build a validate-then-urlopen variant of the same race."""
    return """\
def fetch_callback(target_url):
    if not _is_safe_url(target_url):
        raise ValueError("unsafe destination")
    return urllib.request.urlopen(target_url, timeout=10)
"""


def _redirect_source():
    """Build the original validated redirect handed back to urllib."""
    return """\
class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _is_safe_url(newurl):
            raise urllib.error.URLError("unsafe redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)
"""


def _reassigned_destination_source():
    """Build a flow whose post-validation request uses a fixed address."""
    return """\
def send_alert(url, payload):
    if not _is_safe_url(url):
        return False
    url = "https://93.184.216.34/hook"
    request = urllib.request.Request(url, data=payload)
    opener = urllib.request.build_opener(SafeRedirectHandler())
    opener.open(request, timeout=10)
"""


def _different_destination_source():
    """Build a flow that validates a variable other than the request target."""
    return """\
def send_alert(metadata_url, callback_url, payload):
    if not _is_safe_url(metadata_url):
        return False
    request = urllib.request.Request(callback_url, data=payload)
    opener = urllib.request.build_opener(SafeRedirectHandler())
    opener.open(request, timeout=10)
"""


def _case_distinct_destination_source():
    """Build a Python flow whose target differs only by case."""
    return """\
def send_alert(url, URL, payload):
    if not _is_safe_url(url):
        return False
    return urllib.request.urlopen(URL, timeout=10)
"""


def _attribute_destination_source():
    """Build a flow using an attribute of the validated object, not that object."""
    return """\
def fetch_callback(url):
    if not _is_safe_url(url):
        return False
    return urllib.request.urlopen(url.redirect_target, timeout=10)
"""


def _reassigned_request_source():
    """Build a flow that replaces the guarded request before dispatch."""
    return """\
def send_alert(url, payload):
    if not _is_safe_url(url):
        return False
    request = urllib.request.Request(url, data=payload)
    request = urllib.request.Request("https://93.184.216.34/hook", data=payload)
    opener = urllib.request.build_opener(SafeRedirectHandler())
    opener.open(request, timeout=10)
"""


def _request_attribute_source():
    """Build a flow that dispatches an attribute, not the captured request."""
    return """\
def send_alert(url, payload):
    if not _is_safe_url(url):
        return False
    request = urllib.request.Request(url, data=payload)
    opener = urllib.request.build_opener(SafeRedirectHandler())
    opener.open(request.redirect_request, timeout=10)
"""


def _pinned_transport_source():
    """Build the repaired connection-time pinned transport flow."""
    return """\
def send_alert(url, payload):
    response = post_json_pinned_https(url, payload, timeout=10)
    return 200 <= response.status < 300
"""


def _exact_fixed_source():
    """Replay the verbatim PR #1327 pinned-transport function."""
    return """\
def _send_alert(
    url: str,
    payload: dict[str, Any],
    *,
    org_name: "str | None" = None,
    new_findings: "list[dict[str, Any]] | None" = None,
) -> bool:
    \"\"\"Best-effort POST of a drift alert. Never raises; returns delivery success.

    For Slack Incoming Webhook URLs (host ``hooks.slack.com``) the alert is
    rendered as a Block Kit message so Slack shows a readable card; every other
    URL receives the generic JSON ``payload`` unchanged (backward compatible).
    \"\"\"
    if _is_slack_webhook(url):
        body = _slack_blocks(org_name, payload, new_findings or [])
    else:
        body = payload

    try:
        response = post_json_pinned_https(url, body, timeout=10)
        return 200 <= response.status < 300
    except (PinnedHTTPSFailure, OSError, TypeError, ValueError):
        return False
"""


def _bearer_authenticated_source():
    """Build the credential-bearing family owned by PR #1080."""
    return """\
def deliver(url, token, payload):
    if not _is_safe_url(url):
        return False
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    opener = urllib.request.build_opener(SafeRedirectHandler())
    opener.open(request, timeout=10)
"""


def _prebuilt_bearer_headers_source():
    """Build the PR #1080 shape with credential state prepared before validation."""
    return """\
def deliver(url, token, payload):
    headers = {"Authorization": f"Bearer {token}"}
    if not _is_safe_url(url):
        return False
    request = urllib.request.Request(url, data=payload, headers=headers)
    opener = urllib.request.build_opener(SafeRedirectHandler())
    opener.open(request, timeout=10)
"""


def _long_bearer_request_source():
    """Keep Bearer exclusion wider than every accepted direct-request window."""
    padding = "#" * 1050
    argument_padding = "#" * 180
    return f"""\
def deliver(url, token, payload):
    if not _is_safe_url(url):
        return False
    {padding}
    request = urllib.request.Request(
        url,
        {argument_padding}
        headers={{"Authorization": f"Bearer {{token}}"}},
    )
    opener = urllib.request.build_opener(SafeRedirectHandler())
    opener.open(request, timeout=10)
"""


def _lowercase_bearer_request_source():
    """Treat HTTP header and auth-scheme casing as credential evidence."""
    return """\
def deliver(url, token, payload):
    if not _is_safe_url(url):
        return False
    request = urllib.request.Request(
        url,
        headers={"authorization": f"bearer {token}"},
    )
    opener = urllib.request.build_opener(SafeRedirectHandler())
    opener.open(request, timeout=10)
"""


def _oversized_guard_source():
    """Keep oversized rejection branches outside the bounded detector contract."""
    padding = "#" * 2600
    return f"""\
def send_alert(url, payload):
    if not _is_safe_url(url):
        {padding}
        return False
    request = urllib.request.Request(url, data=payload)
    opener = urllib.request.build_opener(SafeRedirectHandler())
    opener.open(request, timeout=10)
"""


def _oversized_guard_header_source():
    """Keep oversized guard headers outside the bounded detector contract."""
    padding = "#" * 8100
    return f"""\
def send_alert(url, payload):
    if not _is_safe_url(url):  {padding}
        return False
    request = urllib.request.Request(url, data=payload)
    opener = urllib.request.build_opener(SafeRedirectHandler())
    opener.open(request, timeout=10)
"""


@pytest.mark.parametrize(
    "source",
    [
        _direct_request_source(),
        _exact_vulnerable_source(),
        _direct_urlopen_source(),
        _redirect_source(),
    ],
)
def test_packaged_rule_matches_validation_to_connect_races(source):
    """Detect guarded URLs handed to a transport that resolves them again."""
    assert _rule()["pattern"].search(source)


@pytest.mark.parametrize(
    "source",
    [
        _reassigned_destination_source(),
        _different_destination_source(),
        _case_distinct_destination_source(),
        _attribute_destination_source(),
        _reassigned_request_source(),
        _request_attribute_source(),
        _pinned_transport_source(),
        _exact_fixed_source(),
        _bearer_authenticated_source(),
        _prebuilt_bearer_headers_source(),
        _long_bearer_request_source(),
        _lowercase_bearer_request_source(),
        _oversized_guard_source(),
        _oversized_guard_header_source(),
    ],
)
def test_packaged_rule_ignores_non_racing_transports(source):
    """Ignore fixed, unrelated, pinned, and Bearer-owner destinations."""
    assert not _rule()["pattern"].search(source)


@pytest.mark.parametrize(
    "source",
    [
        _direct_request_source(),
        _exact_vulnerable_source(),
        _direct_urlopen_source(),
        _redirect_source(),
    ],
)
def test_scan_file_emits_dns_toctou_finding(source, tmp_path):
    """Emit each supported DNS race through the production file scanner."""
    source_file = tmp_path / "webhook.py"
    source_file.write_text(source, encoding="utf-8")

    findings = [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["category"] == "ssrf"
    assert findings[0]["cwe"] == (
        "CWE-918 - Server-Side Request Forgery",
        "CWE-367 - Time-of-check Time-of-use (TOCTOU) Race Condition",
    )
    assert "pin" in findings[0]["remediation"].lower()


@pytest.mark.parametrize(
    "source",
    [
        _reassigned_destination_source(),
        _different_destination_source(),
        _case_distinct_destination_source(),
        _attribute_destination_source(),
        _reassigned_request_source(),
        _request_attribute_source(),
        _pinned_transport_source(),
        _exact_fixed_source(),
        _bearer_authenticated_source(),
        _prebuilt_bearer_headers_source(),
        _long_bearer_request_source(),
        _lowercase_bearer_request_source(),
        _oversized_guard_source(),
        _oversized_guard_header_source(),
    ],
)
def test_scan_file_ignores_declared_negative_boundaries(source, tmp_path):
    """Keep every declared negative boundary clean in production scanning."""
    source_file = tmp_path / "webhook.py"
    source_file.write_text(source, encoding="utf-8")
    assert all(
        finding["rule_id"] != _RULE_ID
        for finding in _scan_file(source_file, tmp_path)
    )


def test_packaged_rule_declares_validation_prefilter():
    """Skip the bounded flow regex when no URL validation call exists."""
    assert _rule()["required_substrings"] == ("_is_safe_url",)


def test_incident_corpus_pins_vulnerable_and_fixed_heads():
    """Bind the regression corpus to the reviewed Issue #1267 source pair."""
    assert _VULNERABLE_HEAD_SHA == "2949d30718752ea5915c7713ba227e8c19d9e5bf"
    assert _VULNERABLE_BLOB_SHA == "576b990f13b61eda5c6b5ff3910e820498bfd923"
    assert _FIXED_HEAD_SHA == "892a842765cb1d704ed9236ca08de494074d9551"
    assert _FIXED_BLOB_SHA == "801e9961b9f666efb3b3e22ebfb50d5f0429e6d1"
