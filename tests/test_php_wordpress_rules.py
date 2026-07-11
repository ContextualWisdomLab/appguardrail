"""Coverage tests for the PHP / WordPress rule pack (scanner/rules/php-wordpress.yml)."""

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

PHP_RULE_IDS = [
    "php-eval-usage",
    "php-sql-concat",
    "php-unserialize-user-input",
    "php-include-user-input",
    "php-exec-user-input",
    "wordpress-debug-enabled",
]

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], _r)


def _rule(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


def test_php_rules_loaded_and_scoped_to_php_files():
    for rule_id in PHP_RULE_IDS:
        rule = _rule(rule_id)
        assert rule["include_paths"] == ["**/*.php"], rule_id
        # generic language: no extension filter, path glob does the scoping
        assert rule["extensions"] is None, rule_id


def test_php_eval_usage():
    r = _rule("php-eval-usage")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search("eval($_GET['code']);")
    assert r["pattern"].search("eval ( base64_decode($payload) );")
    # similarly named functions must not match
    assert not r["pattern"].search("$score = evaluate($input);")
    assert not r["pattern"].search("$mode = 'eval';")


def test_php_sql_concat():
    r = _rule("php-sql-concat")
    assert r["severity"] == "CRITICAL"
    assert r["pattern"].search(
        'mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET[\'id\']);'
    )
    assert r["pattern"].search('$wpdb->query("DELETE FROM wp_posts WHERE ID = $_POST[id]");')
    assert r["pattern"].search('$wpdb->get_results("SELECT * FROM t WHERE a = $_REQUEST[a]");')
    # parameterized queries must not match
    assert not r["pattern"].search(
        'mysqli_query($conn, "SELECT * FROM users WHERE id = ?");'
    )
    assert not r["pattern"].search(
        '$wpdb->query($wpdb->prepare("SELECT * FROM t WHERE id = %d", $_GET[\'id\']));'
    )
    assert not r["pattern"].search('$wpdb->query($sql);')


def test_php_unserialize_user_input():
    r = _rule("php-unserialize-user-input")
    assert r["severity"] == "CRITICAL"
    assert r["pattern"].search("$obj = unserialize($_COOKIE['session']);")
    assert r["pattern"].search("unserialize(base64_decode($_POST['data']))")
    # safe decoding of request input must not match
    assert not r["pattern"].search("$data = json_decode($_POST['payload'], true);")
    assert not r["pattern"].search("$obj = unserialize($trusted_cache_blob);")


def test_php_include_user_input():
    r = _rule("php-include-user-input")
    assert r["severity"] == "CRITICAL"
    assert r["pattern"].search("include($_GET['page']);")
    assert r["pattern"].search("require_once 'pages/' . $_REQUEST['p'];")
    assert r["pattern"].search("include_once $_POST['template'];")
    # constant/allowlisted includes must not match
    assert not r["pattern"].search("include __DIR__ . '/header.php';")
    assert not r["pattern"].search("require_once ABSPATH . 'wp-settings.php';")


def test_php_exec_user_input():
    r = _rule("php-exec-user-input")
    assert r["severity"] == "CRITICAL"
    assert r["pattern"].search('system("ping " . $_GET[\'host\']);')
    assert r["pattern"].search("exec($_POST['cmd'], $output);")
    assert r["pattern"].search('shell_exec("convert $_REQUEST[file] out.png");')
    # fixed commands and escaped args without superglobals must not match
    assert not r["pattern"].search("system('ls -la /var/www');")
    assert not r["pattern"].search("exec('git pull', $output);")


def test_wordpress_debug_enabled():
    r = _rule("wordpress-debug-enabled")
    assert r["severity"] == "WARNING"
    assert r["pattern"].search("define( 'WP_DEBUG', true );")
    assert r["pattern"].search('define("WP_DEBUG",true);')
    assert not r["pattern"].search("define( 'WP_DEBUG', false );")
    assert not r["pattern"].search("define( 'WP_DEBUG_LOG', true );")


def test_php_rules_fire_end_to_end_on_php_paths_only(tmp_path):
    plugin = tmp_path / "wp-content" / "plugins" / "demo" / "page.php"
    plugin.parent.mkdir(parents=True)
    plugin.write_text(
        "<?php\n"
        "eval($_GET['code']);\n"
        "$wpdb->query(\"DELETE FROM wp_posts WHERE ID = $_POST[id]\");\n"
        "$obj = unserialize($_COOKIE['session']);\n"
        "include($_GET['page']);\n"
        "system(\"ping \" . $_GET['host']);\n"
    )
    config = tmp_path / "wp-config.php"
    config.write_text("<?php\ndefine( 'WP_DEBUG', true );\n")

    findings = _scan_file(plugin, tmp_path) + _scan_file(config, tmp_path)
    fired = {f["rule_id"] for f in findings}
    assert set(PHP_RULE_IDS) <= fired

    # the same code in a non-PHP file must not trigger the pack
    script = tmp_path / "app.js"
    script.write_text("eval($_GET['code']);\n")
    js_fired = {
        f["rule_id"]
        for f in _scan_file(script, tmp_path)
        if f["rule_id"] in PHP_RULE_IDS
    }
    assert js_fired == set()
