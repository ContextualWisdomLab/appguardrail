"""Coverage tests for the Java / Spring security rule pack (scanner/rules/java-spring.yml)."""

import pytest

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], _r)


def _rule(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


_TRUST_ALL_JAVA = (
    "TrustManager[] trustAll = new TrustManager[]{ new X509TrustManager() {\n"
    "    public void checkClientTrusted(X509Certificate[] chain, String authType) {}\n"
    "    public void checkServerTrusted(X509Certificate[] chain, String authType) {}\n"
    "    public X509Certificate[] getAcceptedIssuers() { return null; }\n"
    "}};"
)

_SAFE_TRUST_MANAGER_JAVA = (
    "class DelegatingTrustManager implements X509TrustManager {\n"
    "    public void checkServerTrusted(X509Certificate[] chain, String authType)\n"
    "            throws CertificateException {\n"
    "        defaultTrustManager.checkServerTrusted(chain, authType);\n"
    "    }\n"
    "}"
)

CASES = {
    "java-sql-injection-concat": (
        [
            'stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);',
            'conn.prepareStatement("DELETE FROM orders WHERE owner = " + request.getParameter("owner"));',
            'em.createQuery("FROM Account a WHERE a.name = " + name).getResultList();',
            'em.createNativeQuery("SELECT * FROM t WHERE c = " + value);',
        ],
        [
            'conn.prepareStatement("SELECT * FROM users WHERE id = ?");',
            'em.createQuery("FROM User u WHERE u.name = :name").setParameter("name", name);',
            "stmt.executeQuery(SAFE_CONSTANT_QUERY);",
            'log.info("query took " + elapsed);',
        ],
    ),
    "java-runtime-exec-concat": (
        [
            'Runtime.getRuntime().exec("ping -c 1 " + host);',
            'Runtime.getRuntime().exec("cmd /c type " + fileName);',
            'new ProcessBuilder("sh", "-c", "curl " + url).start();',
        ],
        [
            'Runtime.getRuntime().exec(new String[]{"ls", "-l"});',
            'Runtime.getRuntime().exec("hostname");',
            'new ProcessBuilder("git", "status").start();',
        ],
    ),
    "java-xxe-unsafe-parser": (
        [
            'factory.setFeature("http://xml.org/sax/features/external-general-entities", true);',
            'factory.setFeature("http://xml.org/sax/features/external-parameter-entities", true);',
            'factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);',
            "xif.setProperty(XMLInputFactory.SUPPORT_DTD, true);",
            'xif.setProperty("javax.xml.stream.supportDTD", Boolean.TRUE);',
        ],
        [
            'factory.setFeature("http://xml.org/sax/features/external-general-entities", false);',
            'factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
            "xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);",
            "builder.parse(inputStream);",
        ],
    ),
    "java-trustall-trustmanager": (
        [_TRUST_ALL_JAVA],
        [_SAFE_TRUST_MANAGER_JAVA, "sslContext.init(null, null, new SecureRandom());"],
    ),
    "spring-actuator-exposed": (
        [
            "management.endpoints.web.exposure.include=*",
            'management.endpoints.web.exposure.include: "*"',
            'management:\n  endpoints:\n    web:\n      exposure:\n        include: "*"',
            "exposure:\n  include: '*'",
        ],
        [
            "management.endpoints.web.exposure.include=health,info",
            "exposure:\n  include: health",
            "spring.main.banner-mode=off",
        ],
    ),
}


@pytest.mark.parametrize("rule_id", CASES.keys())
def test_rule_precision(rule_id):
    rule = _rule(rule_id)
    positives, negatives = CASES[rule_id]
    for snippet in positives:
        assert rule["pattern"].search(snippet), f"{rule_id} should match: {snippet!r}"
    for snippet in negatives:
        assert not rule["pattern"].search(
            snippet
        ), f"{rule_id} false-positive on: {snippet!r}"


def test_severities():
    assert _rule("java-sql-injection-concat")["severity"] == "CRITICAL"
    assert _rule("java-runtime-exec-concat")["severity"] == "CRITICAL"
    assert _rule("java-xxe-unsafe-parser")["severity"] == "HIGH"
    assert _rule("java-trustall-trustmanager")["severity"] == "HIGH"
    assert _rule("spring-actuator-exposed")["severity"] == "HIGH"


def test_java_rules_scoped_to_java_files():
    for rule_id in (
        "java-sql-injection-concat",
        "java-runtime-exec-concat",
        "java-xxe-unsafe-parser",
        "java-trustall-trustmanager",
    ):
        assert _rule(rule_id)["extensions"] == [".java"]


def test_actuator_rule_scoped_to_spring_config_paths():
    rule = _rule("spring-actuator-exposed")
    assert rule["extensions"] is None
    assert "**/application*.properties" in rule["include_paths"]
    assert "**/application*.yml" in rule["include_paths"]
    assert "**/application*.yaml" in rule["include_paths"]


def test_no_id_collision_with_builtin_java_rules():
    # java-spring.yml must only add rules that built-ins do not already define.
    origins = {}
    for rule in SCAN_RULES:
        origins.setdefault(rule["id"], set()).add(
            rule.get("origin", "<builtin>") if isinstance(rule, dict) else "<builtin>"
        )
    for rule_id in CASES:
        assert len(origins[rule_id]) == 1, f"duplicate definitions for {rule_id}"


def test_end_to_end_scan_java_file(tmp_path):
    java_file = tmp_path / "UserService.java"
    java_file.write_text(
        "class UserService {\n"
        "    void find(String userId) throws Exception {\n"
        '        stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);\n'
        '        Runtime.getRuntime().exec("ping -c 1 " + userId);\n'
        '        factory.setFeature("http://xml.org/sax/features/external-general-entities", true);\n'
        "    }\n"
        "}\n" + _TRUST_ALL_JAVA,
        encoding="utf-8",
    )
    rule_ids = {finding["rule_id"] for finding in _scan_file(java_file, tmp_path)}
    assert "java-sql-injection-concat" in rule_ids
    assert "java-runtime-exec-concat" in rule_ids
    assert "java-xxe-unsafe-parser" in rule_ids
    assert "java-trustall-trustmanager" in rule_ids


def test_end_to_end_scan_java_rules_ignore_other_extensions(tmp_path):
    js_file = tmp_path / "service.js"
    js_file.write_text(
        'stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);\n',
        encoding="utf-8",
    )
    rule_ids = {finding["rule_id"] for finding in _scan_file(js_file, tmp_path)}
    assert "java-sql-injection-concat" not in rule_ids


def test_end_to_end_scan_actuator_properties(tmp_path):
    config = tmp_path / "application.properties"
    config.write_text(
        "management.endpoints.web.exposure.include=*\n", encoding="utf-8"
    )
    rule_ids = {finding["rule_id"] for finding in _scan_file(config, tmp_path)}
    assert "spring-actuator-exposed" in rule_ids


def test_end_to_end_scan_actuator_yaml_nested(tmp_path):
    config = tmp_path / "application-prod.yml"
    config.write_text(
        'management:\n  endpoints:\n    web:\n      exposure:\n        include: "*"\n',
        encoding="utf-8",
    )
    rule_ids = {finding["rule_id"] for finding in _scan_file(config, tmp_path)}
    assert "spring-actuator-exposed" in rule_ids


def test_end_to_end_actuator_rule_respects_path_scope(tmp_path):
    other = tmp_path / "notes.txt"
    other.write_text(
        "management.endpoints.web.exposure.include=*\n", encoding="utf-8"
    )
    rule_ids = {finding["rule_id"] for finding in _scan_file(other, tmp_path)}
    assert "spring-actuator-exposed" not in rule_ids


def test_end_to_end_safe_java_file_clean(tmp_path):
    java_file = tmp_path / "SafeService.java"
    java_file.write_text(
        "class SafeService {\n"
        "    void find(String userId) throws Exception {\n"
        '        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\n'
        "        ps.setString(1, userId);\n"
        '        new ProcessBuilder("git", "status").start();\n'
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    java_pack_ids = set(CASES)
    rule_ids = {finding["rule_id"] for finding in _scan_file(java_file, tmp_path)}
    assert not (rule_ids & java_pack_ids)
