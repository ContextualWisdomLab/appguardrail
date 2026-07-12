"""Tests for the Python hardening rule pack (second Strix-corpus batch).

Each rule in ``scanner/rules/python-hardening.yml`` targets a Python stdlib
security anti-pattern the existing coverage did not yet reach. These tests
assert each rule matches the vulnerable idiom, does not fire on the safe
alternative, keeps a stable severity, and that an end-to-end scan surfaces
them all while a hardened file stays clean.
"""

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_IDS = {
    "python-tarfile-extractall-untrusted",
    "python-jwt-signature-verification-disabled",
    "python-weak-ssl-tls-version",
    "python-insecure-random-token",
    "python-world-writable-chmod",
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


def test_all_hardening_rules_loaded():
    assert set(_BY_ID) == _RULE_IDS


# ---------------------------------------------------------------------------
# python-tarfile-extractall-untrusted (CWE-22)
# ---------------------------------------------------------------------------


def test_extractall_positive():
    assert _matches("python-tarfile-extractall-untrusted", "tar.extractall(dest)")
    assert _matches("python-tarfile-extractall-untrusted", "zipfile.ZipFile(f).extractall()")


def test_extractall_negative():
    assert not _matches("python-tarfile-extractall-untrusted", "tar.extract(member, path)")
    assert not _matches("python-tarfile-extractall-untrusted", "results.extractall_flag = True")


def test_extractall_severity():
    assert _severity("python-tarfile-extractall-untrusted") == "HIGH"


# ---------------------------------------------------------------------------
# python-jwt-signature-verification-disabled (CWE-347)
# ---------------------------------------------------------------------------


def test_jwt_verify_disabled_positive():
    assert _matches(
        "python-jwt-signature-verification-disabled",
        'jwt.decode(t, options={"verify_signature": False})',
    )
    assert _matches(
        "python-jwt-signature-verification-disabled",
        "jwt.decode(token, key, verify=False)",
    )


def test_jwt_verify_disabled_negative():
    assert not _matches(
        "python-jwt-signature-verification-disabled",
        'jwt.decode(t, key, algorithms=["HS256"])',
    )
    assert not _matches(
        "python-jwt-signature-verification-disabled",
        'jwt.decode(t, key, options={"verify_signature": True})',
    )


def test_jwt_verify_disabled_severity():
    assert _severity("python-jwt-signature-verification-disabled") == "CRITICAL"


# ---------------------------------------------------------------------------
# python-weak-ssl-tls-version (CWE-326)
# ---------------------------------------------------------------------------


def test_weak_tls_positive():
    assert _matches("python-weak-ssl-tls-version", "ctx = ssl.PROTOCOL_TLSv1")
    assert _matches("python-weak-ssl-tls-version", "ssl_version=ssl.PROTOCOL_SSLv3")
    assert _matches("python-weak-ssl-tls-version", "v = ssl.PROTOCOL_TLSv1_1")


def test_weak_tls_negative():
    assert not _matches("python-weak-ssl-tls-version", "ssl.PROTOCOL_TLSv1_2")
    assert not _matches("python-weak-ssl-tls-version", "ssl.PROTOCOL_TLS_CLIENT")


def test_weak_tls_severity():
    assert _severity("python-weak-ssl-tls-version") == "HIGH"


# ---------------------------------------------------------------------------
# python-insecure-random-token (CWE-330)
# ---------------------------------------------------------------------------


def test_insecure_random_positive():
    assert _matches("python-insecure-random-token", "token = random.choice(chars)")
    assert _matches("python-insecure-random-token", "otp = random.randint(1000, 9999)")


def test_insecure_random_negative():
    # random used for a non-security value, and the secure alternative.
    assert not _matches("python-insecure-random-token", "idx = random.randint(0, len(items))")
    assert not _matches("python-insecure-random-token", "secret = secrets.token_hex(16)")


def test_insecure_random_severity():
    assert _severity("python-insecure-random-token") == "MEDIUM"


# ---------------------------------------------------------------------------
# python-world-writable-chmod (CWE-732)
# ---------------------------------------------------------------------------


def test_world_writable_chmod_positive():
    assert _matches("python-world-writable-chmod", "os.chmod(p, 0o777)")
    assert _matches("python-world-writable-chmod", "os.chmod(path, 0o666)")


def test_world_writable_chmod_negative():
    assert not _matches("python-world-writable-chmod", "os.chmod(p, 0o755)")
    assert not _matches("python-world-writable-chmod", "os.chmod(p, 0o600)")


def test_world_writable_chmod_severity():
    assert _severity("python-world-writable-chmod") == "MEDIUM"


# ---------------------------------------------------------------------------
# End-to-end: a vulnerable file flags every rule; a hardened file flags none.
# ---------------------------------------------------------------------------


def test_end_to_end_scan_flags_every_rule(tmp_path):
    vuln = tmp_path / "vuln.py"
    vuln.write_text(
        "import os, ssl, random, tarfile, jwt\n"
        "tar = tarfile.open(path)\n"
        "tar.extractall(dest)\n"
        'claims = jwt.decode(token, key, options={"verify_signature": False})\n'
        "ctx_version = ssl.PROTOCOL_TLSv1\n"
        "reset_token = random.choice(alphabet)\n"
        "os.chmod(target, 0o777)\n",
        encoding="utf-8",
    )
    flagged = {f["rule_id"] for f in _scan_file(vuln, tmp_path)}
    assert _RULE_IDS <= flagged, f"missing: {_RULE_IDS - flagged}"


def test_end_to_end_scan_clean_on_hardened_file(tmp_path):
    safe = tmp_path / "safe.py"
    safe.write_text(
        "import os, ssl, secrets, jwt\n"
        "claims = jwt.decode(token, key, algorithms=['HS256'])\n"
        "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
        "ctx.minimum_version = ssl.TLSVersion.TLSv1_2\n"
        "reset_token = secrets.token_urlsafe(32)\n"
        "os.chmod(target, 0o600)\n",
        encoding="utf-8",
    )
    flagged = {f["rule_id"] for f in _scan_file(safe, tmp_path)}
    assert not (_RULE_IDS & flagged), f"unexpected: {_RULE_IDS & flagged}"
