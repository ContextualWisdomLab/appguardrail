"""Coverage tests for the mobile (React Native / Expo / iOS / Android) rule pack."""

from scanner.cli.appguardrail import SCAN_RULES, _collect_files, _scan_file

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], []).append(_r)


def _rules(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


def _rule(rule_id):
    return _rules(rule_id)[0]


def _matches(rule_id, text):
    return any(r["pattern"].search(text) for r in _rules(rule_id))


def test_react_native_asyncstorage_sensitive_data():
    r = _rule("react-native-asyncstorage-sensitive-data")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search("await AsyncStorage.setItem('accessToken', token);")
    assert r["pattern"].search('AsyncStorage.setItem("refresh_token", rt)')
    assert r["pattern"].search("AsyncStorage.setItem(`user_password`, pw)")
    assert r["pattern"].search("AsyncStorage.setItem('API_KEY', key)")
    # non-sensitive keys must not match
    assert not r["pattern"].search("AsyncStorage.setItem('theme', 'dark')")
    assert not r["pattern"].search("AsyncStorage.setItem('onboardingSeen', '1')")
    # secure storage APIs must not match
    assert not r["pattern"].search("SecureStore.setItemAsync('accessToken', token)")
    assert not r["pattern"].search("EncryptedAsyncStorage.setItem('token', t)")


def test_android_cleartext_traffic_enabled():
    r = _rule("android-cleartext-traffic-enabled")
    assert r["severity"] == "HIGH"
    assert "**/AndroidManifest.xml" in r["include_paths"]
    assert r["pattern"].search('<application android:usesCleartextTraffic="true">')
    assert r["pattern"].search('android:usesCleartextTraffic = "true"')
    assert not r["pattern"].search('android:usesCleartextTraffic="false"')
    assert not r["pattern"].search("<application android:label=\"@string/app_name\">")


def test_android_debuggable_enabled():
    r = _rule("android-debuggable-enabled")
    assert r["severity"] == "HIGH"
    assert "**/AndroidManifest.xml" in r["include_paths"]
    assert r["pattern"].search('<application android:debuggable="true">')
    assert not r["pattern"].search('android:debuggable="false"')
    assert not r["pattern"].search("<application android:allowBackup=\"false\">")


def test_android_allow_backup_enabled():
    r = _rule("android-allow-backup-enabled")
    assert r["severity"] == "WARNING"
    assert "**/AndroidManifest.xml" in r["include_paths"]
    assert r["pattern"].search('<application android:allowBackup="true">')
    assert not r["pattern"].search('android:allowBackup="false"')
    assert not r["pattern"].search('android:fullBackupContent="@xml/backup_rules"')


def test_ios_ats_arbitrary_loads_enabled():
    rules = _rules("ios-ats-arbitrary-loads-enabled")
    assert all(r["severity"] == "HIGH" for r in rules)
    rid = "ios-ats-arbitrary-loads-enabled"
    # Info.plist form (key and value may span lines)
    assert _matches(rid, "<key>NSAllowsArbitraryLoads</key>\n\t<true/>")
    assert _matches(rid, "<key>NSAllowsArbitraryLoads</key><true />")
    # Expo app.json / app.config form
    assert _matches(rid, '"NSAllowsArbitraryLoads": true')
    # ATS left enabled must not match
    assert not _matches(rid, "<key>NSAllowsArbitraryLoads</key>\n\t<false/>")
    assert not _matches(rid, '"NSAllowsArbitraryLoads": false')
    assert not _matches(rid, "<key>NSAllowsArbitraryLoadsInWebContent</key>\n<false/>")


def test_react_native_webview_wildcard_origin():
    r = _rule("react-native-webview-wildcard-origin")
    assert r["severity"] == "WARNING"
    assert r["pattern"].search("<WebView originWhitelist={['*']} source={{ uri }} />")
    assert r["pattern"].search('originWhitelist={["*"]}')
    assert r["pattern"].search("originWhitelist={ [ '*' ] }")
    assert not r["pattern"].search("originWhitelist={['https://example.com']}")
    assert not r["pattern"].search("originWhitelist={['about:blank']}")


def test_mobile_rules_end_to_end_scan(tmp_path):
    (tmp_path / "android/app/src/main").mkdir(parents=True)
    (tmp_path / "android/app/src/main/AndroidManifest.xml").write_text(
        '<application android:allowBackup="true" '
        'android:usesCleartextTraffic="true" '
        'android:debuggable="true">'
    )
    (tmp_path / "ios").mkdir()
    (tmp_path / "ios/Info.plist").write_text(
        "<key>NSAllowsArbitraryLoads</key>\n<true/>"
    )
    (tmp_path / "app.json").write_text(
        '{"ios": {"infoPlist": {"NSAllowsArbitraryLoads": true}}}'
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src/auth.ts").write_text(
        "await AsyncStorage.setItem('accessToken', token);\n"
    )
    (tmp_path / "src/Web.jsx").write_text(
        "<WebView originWhitelist={['*']} source={{ uri: url }} />\n"
    )
    # negatives: secure storage and docs must stay clean
    (tmp_path / "src/safe.ts").write_text(
        "await SecureStore.setItemAsync('accessToken', token);\n"
        "AsyncStorage.setItem('theme', 'dark');\n"
    )
    (tmp_path / "notes.md").write_text('android:debuggable="true" example\n')

    findings = []
    for file_path in _collect_files(tmp_path):
        findings.extend(_scan_file(file_path, tmp_path))

    mobile_ids = {
        "react-native-asyncstorage-sensitive-data",
        "android-cleartext-traffic-enabled",
        "android-debuggable-enabled",
        "android-allow-backup-enabled",
        "ios-ats-arbitrary-loads-enabled",
        "react-native-webview-wildcard-origin",
    }
    hits = [f for f in findings if f["rule_id"] in mobile_ids]
    assert {f["rule_id"] for f in hits} == mobile_ids
    # AndroidManifest-scoped rules only fire on the manifest
    for finding in hits:
        if finding["rule_id"].startswith("android-"):
            assert finding["file"].endswith("AndroidManifest.xml")
    # negatives stayed clean
    assert not any(
        f["file"].endswith(("safe.ts", "notes.md")) for f in hits
    )
