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


def test_is_safe_url_unsupported_schemes():
    assert not _is_safe_url("file:///etc/passwd")
    assert not _is_safe_url("ftp://example.com")
    assert not _is_safe_url("gopher://example.com")


def test_is_safe_url_unresolvable_domain():
    # An unresolvable domain is considered safe by _is_safe_url
    assert _is_safe_url("http://this-domain-should-not-exist-12345.com/")


def test_is_safe_url_unspecified_ips():
    assert not _is_safe_url("http://0.0.0.0/")
    assert not _is_safe_url("http://[::]/")


def test_is_safe_url_multicast_ips():
    assert not _is_safe_url("http://224.0.0.1/")
    assert not _is_safe_url("http://[ff02::1]/")
