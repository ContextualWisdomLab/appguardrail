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


def test_is_safe_url_unresolvable_domain():
    # An unresolvable domain is considered safe by _is_safe_url
    assert _is_safe_url("http://this-domain-should-not-exist-12345.com/")


def test_is_safe_url_mapped_ips():
    assert not _is_safe_url("http://[::ffff:127.0.0.1]/")
    assert not _is_safe_url("http://[::ffff:192.168.1.1]/")


def test_is_safe_url_reserved_and_not_global_ips():
    assert not _is_safe_url("http://255.255.255.255/")
    assert not _is_safe_url("http://0.0.0.0/")

def test_safe_redirect_handler_blocks_unsafe():
    from appguardrail_core.controlplane import SafeRedirectHandler
    import urllib.error
    import urllib.request
    import pytest

    handler = SafeRedirectHandler()

    class FakeReq:
        pass

    with pytest.raises(urllib.error.URLError, match="Unsafe redirect URL blocked: http://127.0.0.1/"):
        handler.redirect_request(FakeReq(), None, 302, "Found", {}, "http://127.0.0.1/")

    with pytest.raises(urllib.error.URLError, match="Unsafe redirect URL blocked: http://169.254.169.254/"):
        handler.redirect_request(FakeReq(), None, 301, "Moved Permanently", {}, "http://169.254.169.254/")


def test_safe_redirect_handler_allows_safe(monkeypatch):
    from appguardrail_core.controlplane import SafeRedirectHandler
    import urllib.request

    handler = SafeRedirectHandler()

    class FakeReq:
        pass

    def _fake_super_redirect(*args, **kwargs):
        return "allowed"

    # Monkeypatch to avoid actual urllib recursion
    monkeypatch.setattr(urllib.request.HTTPRedirectHandler, "redirect_request", _fake_super_redirect)

    assert handler.redirect_request(FakeReq(), None, 302, "Found", {}, "http://google.com/") == "allowed"
