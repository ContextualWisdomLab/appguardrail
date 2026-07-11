"""Coverage tests for the Kotlin / Android-native rule pack (kotlin-android.yml)."""

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], []).append(_r)

KOTLIN_RULE_IDS = [
    "kotlin-webview-universal-file-access",
    "kotlin-sql-injection-raw",
    "kotlin-hardcoded-encryption-key",
    "kotlin-trust-all-certs",
    "kotlin-world-accessible-prefs",
    "kotlin-log-sensitive-data",
]


def _rules(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


def _matches(rule_id, text):
    return any(r["pattern"].search(text) for r in _rules(rule_id))


# ---------------------------------------------------------------------------
# Rule loading, severity, and Kotlin path scoping
# ---------------------------------------------------------------------------


def test_kotlin_rules_loaded_and_scoped_to_kotlin_files():
    for rule_id in KOTLIN_RULE_IDS:
        for r in _rules(rule_id):
            assert r["extensions"] is None  # languages: [generic]
            assert "**/*.kt" in r["include_paths"]
            assert "**/*.kts" in r["include_paths"]


def test_kotlin_rule_severities():
    expected = {
        "kotlin-webview-universal-file-access": "CRITICAL",
        "kotlin-sql-injection-raw": "CRITICAL",
        "kotlin-hardcoded-encryption-key": "CRITICAL",
        "kotlin-trust-all-certs": "HIGH",
        "kotlin-world-accessible-prefs": "HIGH",
        "kotlin-log-sensitive-data": "WARNING",
    }
    for rule_id, severity in expected.items():
        for r in _rules(rule_id):
            assert r["severity"] == severity, rule_id


# ---------------------------------------------------------------------------
# kotlin-webview-universal-file-access
# ---------------------------------------------------------------------------


def test_webview_file_access_positives():
    rid = "kotlin-webview-universal-file-access"
    assert _matches(rid, "webView.settings.allowUniversalAccessFromFileURLs = true")
    assert _matches(rid, "settings.allowFileAccessFromFileURLs = true")
    assert _matches(rid, "settings.setAllowUniversalAccessFromFileURLs(true)")
    assert _matches(rid, "settings.setAllowFileAccessFromFileURLs( true )")


def test_webview_file_access_negatives():
    rid = "kotlin-webview-universal-file-access"
    # Secure default kept explicitly.
    assert not _matches(rid, "settings.allowUniversalAccessFromFileURLs = false")
    assert not _matches(rid, "settings.setAllowFileAccessFromFileURLs(false)")
    # Plain allowFileAccess is a different, far less severe setting.
    assert not _matches(rid, "settings.allowFileAccess = true")
    assert not _matches(rid, "settings.javaScriptEnabled = true")


# ---------------------------------------------------------------------------
# kotlin-sql-injection-raw
# ---------------------------------------------------------------------------


def test_sql_injection_raw_positives():
    rid = "kotlin-sql-injection-raw"
    # Kotlin string template interpolation.
    assert _matches(rid, 'db.rawQuery("SELECT * FROM users WHERE name = $name", null)')
    assert _matches(rid, 'db.execSQL("DELETE FROM notes WHERE id = ${note.id}")')
    # Plain string concatenation.
    assert _matches(rid, 'db.rawQuery("SELECT * FROM users WHERE id = " + userId, null)')
    assert _matches(rid, 'database.execSQL("UPDATE t SET v = " + value)')


def test_sql_injection_raw_negatives():
    rid = "kotlin-sql-injection-raw"
    # Parameterized queries are safe.
    assert not _matches(
        rid, 'db.rawQuery("SELECT * FROM users WHERE id = ?", arrayOf(userId))'
    )
    assert not _matches(rid, 'db.execSQL("CREATE TABLE users (id INTEGER PRIMARY KEY)")')
    # Escaped dollar sign is a literal, not interpolation.
    assert not _matches(rid, 'db.execSQL("UPDATE t SET label = \\$100")')


# ---------------------------------------------------------------------------
# kotlin-hardcoded-encryption-key
# ---------------------------------------------------------------------------


def test_hardcoded_encryption_key_positives():
    rid = "kotlin-hardcoded-encryption-key"
    # Assemble the secret-shaped fixture at runtime so the repo itself stays
    # free of literal key material (self-scan + push protection).
    literal_key = "0123456789" + "abcdef"
    snippet = 'val key = SecretKeySpec("' + literal_key + '".toByteArray(), "AES")'
    assert _matches(rid, snippet)
    spaced = 'SecretKeySpec( "' + literal_key + '" .toByteArray(Charsets.UTF_8), "AES")'
    assert _matches(rid, spaced)


def test_hardcoded_encryption_key_negatives():
    rid = "kotlin-hardcoded-encryption-key"
    assert not _matches(rid, 'val key = SecretKeySpec(keyBytes, "AES")')
    assert not _matches(
        rid, 'val key = SecretKeySpec(keyStore.getKey(alias, null).encoded, "AES")'
    )


# ---------------------------------------------------------------------------
# kotlin-trust-all-certs
# ---------------------------------------------------------------------------


def test_trust_all_certs_positives():
    rid = "kotlin-trust-all-certs"
    assert _matches(
        rid,
        "override fun checkServerTrusted("
        "chain: Array<X509Certificate>?, authType: String?) {}",
    )
    multiline = (
        "override fun checkServerTrusted(\n"
        "    chain: Array<X509Certificate>?,\n"
        "    authType: String?,\n"
        ") {\n"
        "}\n"
    )
    assert _matches(rid, multiline)


def test_trust_all_certs_negatives():
    rid = "kotlin-trust-all-certs"
    assert not _matches(
        rid,
        "override fun checkServerTrusted("
        "chain: Array<X509Certificate>?, authType: String?) {"
        " defaultTrustManager.checkServerTrusted(chain, authType) }",
    )
    assert not _matches(rid, "trustManager.checkServerTrusted(chain, authType)")


# ---------------------------------------------------------------------------
# kotlin-world-accessible-prefs
# ---------------------------------------------------------------------------


def test_world_accessible_prefs_positives():
    rid = "kotlin-world-accessible-prefs"
    assert _matches(
        rid, 'getSharedPreferences("session", Context.MODE_WORLD_READABLE)'
    )
    assert _matches(rid, 'openFileOutput("cache.bin", MODE_WORLD_WRITEABLE)')


def test_world_accessible_prefs_negatives():
    rid = "kotlin-world-accessible-prefs"
    assert not _matches(
        rid, 'getSharedPreferences("session", Context.MODE_PRIVATE)'
    )
    assert not _matches(rid, 'openFileOutput("cache.bin", Context.MODE_APPEND)')


# ---------------------------------------------------------------------------
# kotlin-log-sensitive-data
# ---------------------------------------------------------------------------


def test_log_sensitive_data_positives():
    rid = "kotlin-log-sensitive-data"
    assert _matches(rid, 'Log.d(TAG, "password is $password")')
    assert _matches(rid, 'Log.i("Auth", "session ${authToken}")')
    assert _matches(rid, 'Log.e(TAG, "login failed for key: " + apiKey)')
    assert _matches(rid, 'Log.v(TAG, "using " + clientSecret)')


def test_log_sensitive_data_negatives():
    rid = "kotlin-log-sensitive-data"
    assert not _matches(rid, 'Log.d(TAG, "user tapped submit")')
    assert not _matches(rid, 'Log.e(TAG, "network error", exception)')
    assert not _matches(rid, 'Log.i(TAG, "loaded $count items")')


# ---------------------------------------------------------------------------
# End-to-end: rules fire on .kt/.kts files and stay silent elsewhere
# ---------------------------------------------------------------------------

_VULNERABLE_KOTLIN = (
    "package com.example.app\n"
    "\n"
    "class Repo(private val db: SQLiteDatabase) {\n"
    "    fun find(name: String) =\n"
    '        db.rawQuery("SELECT * FROM users WHERE name = $name", null)\n'
    "\n"
    "    fun configure(webView: WebView) {\n"
    "        webView.settings.allowUniversalAccessFromFileURLs = true\n"
    "        val prefs = context.getSharedPreferences(\n"
    '            "session", Context.MODE_WORLD_READABLE)\n'
    '        Log.d(TAG, "session token $authToken")\n'
    "    }\n"
    "\n"
    "    fun trustAll() = object : X509TrustManager {\n"
    "        override fun checkServerTrusted(\n"
    "            chain: Array<X509Certificate>?, authType: String?) {}\n"
    "    }\n"
    "}\n"
)


def test_scan_file_detects_kotlin_rules_end_to_end(tmp_path):
    kt_file = tmp_path / "Repo.kt"
    key_line = (
        'val key = SecretKeySpec("' + "0123456789" + 'abcdef".toByteArray(), "AES")\n'
    )
    kt_file.write_text(_VULNERABLE_KOTLIN + key_line)

    findings = _scan_file(kt_file, tmp_path)
    found_ids = {f["rule_id"] for f in findings}
    for rule_id in KOTLIN_RULE_IDS:
        assert rule_id in found_ids, f"{rule_id} did not fire end-to-end"

    by_id = {f["rule_id"]: f for f in findings}
    assert by_id["kotlin-sql-injection-raw"]["severity"] == "CRITICAL"
    assert by_id["kotlin-trust-all-certs"]["severity"] == "HIGH"
    assert by_id["kotlin-log-sensitive-data"]["severity"] == "WARNING"


def test_scan_file_kotlin_rules_fire_on_kts(tmp_path):
    kts_file = tmp_path / "setup.gradle.kts"
    kts_file.write_text('db.execSQL("DELETE FROM t WHERE id = " + id)\n')
    found_ids = {f["rule_id"] for f in _scan_file(kts_file, tmp_path)}
    assert "kotlin-sql-injection-raw" in found_ids


def test_scan_file_kotlin_rules_skip_non_kotlin_paths(tmp_path):
    other_file = tmp_path / "repo.ts"
    other_file.write_text(_VULNERABLE_KOTLIN)
    found_ids = {f["rule_id"] for f in _scan_file(other_file, tmp_path)}
    assert not (found_ids & set(KOTLIN_RULE_IDS))


def test_scan_file_clean_kotlin_has_no_kotlin_findings(tmp_path):
    kt_file = tmp_path / "Safe.kt"
    kt_file.write_text(
        "package com.example.app\n"
        "\n"
        "class Repo(private val db: SQLiteDatabase) {\n"
        "    fun find(id: String) =\n"
        '        db.rawQuery("SELECT * FROM users WHERE id = ?", arrayOf(id))\n'
        "\n"
        "    fun prefs(context: Context) =\n"
        '        context.getSharedPreferences("session", Context.MODE_PRIVATE)\n'
        "\n"
        '    fun log() = Log.d(TAG, "user tapped submit")\n'
        "}\n"
    )
    found_ids = {f["rule_id"] for f in _scan_file(kt_file, tmp_path)}
    assert not (found_ids & set(KOTLIN_RULE_IDS))
