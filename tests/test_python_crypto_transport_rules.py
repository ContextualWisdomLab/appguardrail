"""Tests for the Python cryptography & transport-security rule pack (batch 3).

Each rule in ``scanner/rules/python-crypto-transport.yml`` targets a broken
cipher, disabled TLS verification, a cleartext protocol client, or a Django
XSS sink. These tests assert each rule matches the vulnerable idiom, does not
fire on the safe alternative, keeps a stable severity, and that an end-to-end
scan surfaces them all while a hardened file stays clean.
"""

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_IDS = {
    "python-weak-cipher-mode",
    "python-ssl-verification-disabled",
    "python-cleartext-protocol-client",
    "python-django-mark-safe-dynamic",
}

_BY_ID = {}
for _rule in SCAN_RULES:
    if _rule["id"] in _RULE_IDS:
        _BY_ID.setdefault(_rule["id"], []).append(_rule)


def _rules(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


def _matches(rule_id, text):
    return any(rule["pattern"].search(text) for rule in _rules(rule_id))


def _severity(rule_id):
    severities = {rule["severity"] for rule in _rules(rule_id)}
    assert len(severities) == 1, f"{rule_id} has inconsistent severity"
    return severities.pop()


def test_all_crypto_transport_rules_loaded():
    assert set(_BY_ID) == _RULE_IDS


# ---------------------------------------------------------------------------
# python-weak-cipher-mode (CWE-327)
# ---------------------------------------------------------------------------


def test_weak_cipher_positive():
    assert _matches("python-weak-cipher-mode", "cipher = AES.new(key, AES.MODE_ECB)")
    assert _matches("python-weak-cipher-mode", "c = DES.new(key, DES.MODE_ECB)")
    assert _matches("python-weak-cipher-mode", "s = ARC4.new(key)")


def test_weak_cipher_negative():
    assert not _matches("python-weak-cipher-mode", "AES.new(key, AES.MODE_GCM)")
    assert not _matches("python-weak-cipher-mode", "AES.new(key, AES.MODE_CBC, iv)")
    assert not _matches("python-weak-cipher-mode", "nodes.new(payload)")


def test_weak_cipher_severity():
    assert _severity("python-weak-cipher-mode") == "HIGH"


# ---------------------------------------------------------------------------
# python-ssl-verification-disabled (CWE-295)
# ---------------------------------------------------------------------------


def test_ssl_verification_disabled_positive():
    assert _matches("python-ssl-verification-disabled", "ctx.verify_mode = ssl.CERT_NONE")
    assert _matches("python-ssl-verification-disabled", "context.check_hostname = False")


def test_ssl_verification_disabled_negative():
    assert not _matches("python-ssl-verification-disabled", "ctx.verify_mode = ssl.CERT_REQUIRED")
    assert not _matches("python-ssl-verification-disabled", "context.check_hostname = True")


def test_ssl_verification_disabled_severity():
    assert _severity("python-ssl-verification-disabled") == "HIGH"


# ---------------------------------------------------------------------------
# python-cleartext-protocol-client (CWE-319)
# ---------------------------------------------------------------------------


def test_cleartext_protocol_positive():
    assert _matches("python-cleartext-protocol-client", "conn = ftplib.FTP(host)")
    assert _matches("python-cleartext-protocol-client", "tn = telnetlib.Telnet(host, 23)")
    assert _matches("python-cleartext-protocol-client", "p = poplib.POP3(host)")


def test_cleartext_protocol_negative():
    assert not _matches("python-cleartext-protocol-client", "conn = ftplib.FTP_TLS(host)")
    assert not _matches("python-cleartext-protocol-client", "p = poplib.POP3_SSL(host)")


def test_cleartext_protocol_severity():
    assert _severity("python-cleartext-protocol-client") == "MEDIUM"


# ---------------------------------------------------------------------------
# python-django-mark-safe-dynamic (CWE-79)
# ---------------------------------------------------------------------------


def test_mark_safe_positive():
    assert _matches("python-django-mark-safe-dynamic", "return mark_safe(user_bio)")
    assert _matches("python-django-mark-safe-dynamic", "html = mark_safe(render_snippet(x))")


def test_mark_safe_negative():
    # A constant, developer-authored HTML string is the intended safe use.
    assert not _matches("python-django-mark-safe-dynamic", "mark_safe('<b>static</b>')")
    assert not _matches("python-django-mark-safe-dynamic", 'mark_safe("<hr>")')


def test_mark_safe_severity():
    assert _severity("python-django-mark-safe-dynamic") == "MEDIUM"


# ---------------------------------------------------------------------------
# End-to-end: a vulnerable file flags every rule; a hardened file flags none.
# ---------------------------------------------------------------------------


def test_end_to_end_scan_flags_every_rule(tmp_path):
    vuln = tmp_path / "vuln.py"
    vuln.write_text(
        "import ssl, ftplib\n"
        "from Crypto.Cipher import AES\n"
        "from django.utils.safestring import mark_safe\n"
        "cipher = AES.new(key, AES.MODE_ECB)\n"
        "ctx.check_hostname = False\n"
        "conn = ftplib.FTP(host)\n"
        "html = mark_safe(user_bio)\n",
        encoding="utf-8",
    )
    flagged = {f["rule_id"] for f in _scan_file(vuln, tmp_path)}
    assert _RULE_IDS <= flagged, f"missing: {_RULE_IDS - flagged}"


def test_end_to_end_scan_clean_on_hardened_file(tmp_path):
    safe = tmp_path / "safe.py"
    safe.write_text(
        "import ssl, ftplib\n"
        "from Crypto.Cipher import AES\n"
        "from django.utils.safestring import mark_safe\n"
        "cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)\n"
        "ctx = ssl.create_default_context()\n"
        "conn = ftplib.FTP_TLS(host)\n"
        "html = mark_safe('<b>static banner</b>')\n",
        encoding="utf-8",
    )
    flagged = {f["rule_id"] for f in _scan_file(safe, tmp_path)}
    assert not (_RULE_IDS & flagged), f"unexpected: {_RULE_IDS & flagged}"
