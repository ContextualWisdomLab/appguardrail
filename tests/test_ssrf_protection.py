import socket

import appguardrail_core.controlplane as controlplane
from appguardrail_core.controlplane import _is_safe_url


def test_is_safe_url_public_domains():
    assert _is_safe_url("http://google.com/")
    assert _is_safe_url("https://github.com/")


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


def test_is_safe_url_unresolvable_domain(monkeypatch):
    # DNS failures are fail-closed; otherwise the later request could resolve
    # differently and reach a private address.
    monkeypatch.setattr(
        controlplane.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(socket.gaierror()),
    )
    assert not _is_safe_url("http://this-domain-should-not-exist-12345.com/")


def test_is_safe_url_mapped_ips():
    assert not _is_safe_url("http://[::ffff:127.0.0.1]/")
    assert not _is_safe_url("http://[::ffff:192.168.1.1]/")


def test_is_safe_url_reserved_and_not_global_ips():
    assert not _is_safe_url("http://255.255.255.255/")
    assert not _is_safe_url("http://0.0.0.0/")
