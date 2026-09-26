import pytest

from appguardrail_core import controlplane
from appguardrail_core.controlplane import _is_safe_url, _send_alert
from appguardrail_core.pinned_https import PinnedHTTPSResponse
from scanner.cli.appguardrail import _is_safe_url as _cli_is_safe_url


@pytest.mark.parametrize(
    "validator",
    [_is_safe_url, _cli_is_safe_url],
    ids=["controlplane", "cli"],
)
def test_is_safe_url_requires_public_https(validator):
    assert not validator("http://8.8.8.8/")
    assert validator("https://8.8.8.8/")

@pytest.mark.parametrize(
    "validator",
    [_is_safe_url, _cli_is_safe_url],
    ids=["controlplane", "cli"],
)
@pytest.mark.parametrize(
    "value",
    [123, True, None, [], {}],
    ids=["integer", "boolean", "none", "list", "mapping"],
)
def test_is_safe_url_invalid_types(validator, value):
    assert not validator(value)


@pytest.mark.parametrize(
    "validator",
    [_is_safe_url, _cli_is_safe_url],
    ids=["controlplane", "cli"],
)
@pytest.mark.parametrize(
    "url",
    [
        "http://",
        "https://",
        "http://user@",
        "http:///",
        "http://?query",
        "http://#fragment",
    ],
)
def test_is_safe_url_rejects_empty_hostname(validator, url):
    assert not validator(url)


def test_is_safe_url_ipv4_localhost():
    assert not _is_safe_url("http://127.0.0.1/")
    assert not _is_safe_url("http://127.0.0.1:8080/")


def test_is_safe_url_ipv6_localhost():
    assert not _is_safe_url("http://[::1]/")
    assert not _is_safe_url("http://[::1]:8080/")
    assert not _is_safe_url("http://[0000:0000:0000:0000:0000:0000:0000:0001]/")


def test_is_safe_url_localhost_domain():
    assert not _is_safe_url("http://localhost/")
    assert not _is_safe_url("http://localhost:8080/")


def test_is_safe_url_private_ips():
    assert not _is_safe_url("http://10.0.0.1/")
    assert not _is_safe_url("http://192.168.1.1/")
    assert not _is_safe_url("http://172.16.0.1/")


def test_is_safe_url_unspecified_ips():
    assert not _is_safe_url("http://0.0.0.0/")
    assert not _is_safe_url("http://[::]/")


def test_is_safe_url_multicast_ips():
    assert not _is_safe_url("http://224.0.0.1/")
    assert not _is_safe_url("http://[ff00::1]/")
    assert not _is_safe_url("http://[ff02::1]/")


def test_is_safe_url_unsupported_schemes():
    assert not _is_safe_url("file:///etc/passwd")
    assert not _is_safe_url("ftp://example.com")
    assert not _is_safe_url("gopher://example.com")


@pytest.mark.parametrize(
    "url",
    ["https://8.8.8.8:0/", "https://8.8.8.8:65536/", "https://8.8.8.8:not-a-port/"],
)
def test_is_safe_url_rejects_invalid_ports(url):
    assert not _is_safe_url(url)


def test_is_safe_url_mapped_ips():
    assert not _is_safe_url("http://[::ffff:127.0.0.1]/")
    assert not _is_safe_url("http://[::ffff:192.168.1.1]/")


def test_is_safe_url_reserved_and_not_global_ips():
    assert not _is_safe_url("http://255.255.255.255/")
    assert not _is_safe_url("http://0.0.0.0/")


def test_push_findings_unsafe_url_handled_properly(monkeypatch, capsys):
    from scanner.cli.appguardrail import _push_findings

    monkeypatch.setenv("APPGUARDRAIL_API_KEY", "dummy")

    _push_findings("http://127.0.0.1/", [])
    captured = capsys.readouterr()
    assert (
        "URL must be a public HTTPS URL"
        in captured.err
    )


def test_send_alert_uses_dns_pinned_https_transport(monkeypatch):
    calls = []

    def deliver(url, payload, *, timeout):
        calls.append((url, payload, timeout))
        return PinnedHTTPSResponse(204, "No Content", (), b"")

    monkeypatch.setattr(controlplane, "post_json_pinned_https", deliver, raising=False)

    payload = {"event": "drift.new_blocking"}
    assert _send_alert("https://8.8.8.8/hook", payload)
    assert calls == [("https://8.8.8.8/hook", payload, 10)]
