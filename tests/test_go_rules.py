"""Coverage tests for the Go security rule pack (scanner/rules/go.yml)."""

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], _r)

GO_RULE_IDS = [
    "go-sql-injection-sprintf",
    "go-command-injection",
    "go-tls-insecure-skip-verify",
    "go-weak-random-token",
    "go-hardcoded-jwt-signing-key",
    "go-pprof-import-exposed",
]


def _rule(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


def _rules(rule_id):
    """All compiled variants of a rule (one per pattern-regex)."""
    matched = [r for r in SCAN_RULES if r["id"] == rule_id]
    assert matched, f"rule not loaded: {rule_id}"
    return matched


def _search(rule_id, text):
    return any(r["pattern"].search(text) for r in _rules(rule_id))


def test_go_rules_all_loaded_and_scoped_to_go_files():
    for rule_id in GO_RULE_IDS:
        for r in _rules(rule_id):
            assert r["include_paths"] == ["**/*.go"], rule_id
            # languages: [generic] compiles with no extension filter;
            # scoping happens purely through the path glob.
            assert not r["extensions"], rule_id


def test_go_sql_injection_sprintf():
    rule_id = "go-sql-injection-sprintf"
    assert _rule(rule_id)["severity"] == "CRITICAL"
    # positives: Sprintf-built SQL and string concatenation
    assert _search(
        rule_id,
        'rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))',
    )
    assert _search(
        rule_id,
        'db.QueryRowContext(ctx, "SELECT name FROM users WHERE id = " + userID)',
    )
    assert _search(rule_id, 'db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s", table))')
    # negatives: parameterized queries and non-SQL Sprintf
    assert not _search(
        rule_id, 'db.QueryContext(ctx, "SELECT * FROM users WHERE id = $1", id)'
    )
    assert not _search(rule_id, 'db.Query("SELECT COUNT(*) FROM users")')
    assert not _search(rule_id, 'msg := fmt.Sprintf("hello %s", name)')


def test_go_command_injection():
    rule_id = "go-command-injection"
    assert _rule(rule_id)["severity"] == "CRITICAL"
    # positives: shell -c with a variable or concatenated command string
    assert _search(rule_id, 'out, err := exec.Command("sh", "-c", userCmd).Output()')
    assert _search(
        rule_id, 'exec.CommandContext(ctx, "/bin/bash", "-c", "ping -c 1 " + host)'
    )
    # negatives: fixed literal command, direct argv invocation
    assert not _search(rule_id, 'exec.Command("sh", "-c", "echo hello")')
    assert not _search(rule_id, 'exec.CommandContext(ctx, "ping", "-c", "1", host)')
    assert not _search(rule_id, 'exec.Command("ls", "-la", dir)')


def test_go_tls_insecure_skip_verify():
    rule_id = "go-tls-insecure-skip-verify"
    assert _rule(rule_id)["severity"] == "HIGH"
    assert _search(rule_id, "cfg := &tls.Config{InsecureSkipVerify: true}")
    assert _search(rule_id, "InsecureSkipVerify:true,")
    assert not _search(rule_id, "cfg := &tls.Config{InsecureSkipVerify: false}")
    assert not _search(rule_id, "InsecureSkipVerify: cfg.AllowInsecure")


def test_go_weak_random_token():
    rule_id = "go-weak-random-token"
    assert _rule(rule_id)["severity"] == "HIGH"
    # positives: math/rand output assigned to a security-sensitive name
    assert _search(rule_id, 'token := fmt.Sprintf("%06d", rand.Intn(1000000))')
    assert _search(rule_id, "otpCode = rand.Int31n(1000000)")
    assert _search(rule_id, "sessionID := strconv.FormatInt(rand.Int63(), 16)")
    # negatives: non-sensitive uses and crypto/rand APIs
    assert not _search(rule_id, "delay := rand.Intn(100)")
    assert not _search(rule_id, "n, err := rand.Read(tokenBytes)")
    assert not _search(rule_id, "token := generateSecureToken()")


def test_go_hardcoded_jwt_signing_key():
    rule_id = "go-hardcoded-jwt-signing-key"
    assert _rule(rule_id)["severity"] == "CRITICAL"
    # assemble the fixture key at runtime so no literal secret lands in the repo
    fake_key = "hs256-" + "signing-" + "key-value"
    assert _search(rule_id, f'signed, err := token.SignedString([]byte("{fake_key}"))')
    assert not _search(
        rule_id, 'token.SignedString([]byte(os.Getenv("JWT_SECRET")))'
    )
    assert not _search(rule_id, "token.SignedString(signingKey)")


def test_go_pprof_import_exposed():
    rule_id = "go-pprof-import-exposed"
    assert _rule(rule_id)["severity"] == "WARNING"
    assert _search(rule_id, '\t_ "net/http/pprof"\n')
    assert _search(rule_id, '    _ "net/http/pprof"')
    # commented-out import and the plain net/http import must not match
    assert not _search(rule_id, '\t// _ "net/http/pprof"\n')
    assert not _search(rule_id, '\t"net/http"\n')


def test_go_rules_end_to_end_scan(tmp_path):
    vulnerable = tmp_path / "main.go"
    vulnerable.write_text(
        "package main\n"
        "\n"
        "import (\n"
        '\t"database/sql"\n'
        '\t"fmt"\n'
        '\t"math/rand"\n'
        '\t"os/exec"\n'
        '\t_ "net/http/pprof"\n'
        ")\n"
        "\n"
        "func handler(db *sql.DB, id string, host string, userCmd string) {\n"
        '\trows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))\n'
        '\tout, _ := exec.Command("sh", "-c", userCmd).Output()\n'
        "\tcfg := &tls.Config{InsecureSkipVerify: true}\n"
        '\ttoken := fmt.Sprintf("%06d", rand.Intn(1000000))\n'
        '\tsigned, _ := jwtToken.SignedString([]byte("'
        + "hs256-" + "signing-" + "key-value"
        + '"))\n'
        "\t_, _, _, _, _ = rows, out, cfg, token, signed\n"
        "}\n",
        encoding="utf-8",
    )
    fired = {
        f["rule_id"]
        for f in _scan_file(vulnerable, tmp_path)
        if f["rule_id"].startswith("go-")
    }
    assert fired == set(GO_RULE_IDS)

    safe = tmp_path / "safe.go"
    safe.write_text(
        "package main\n"
        "\n"
        "import (\n"
        '\t"crypto/rand"\n'
        '\t"database/sql"\n'
        '\t"os"\n'
        '\t"os/exec"\n'
        ")\n"
        "\n"
        "func safeHandler(db *sql.DB, id string, host string) {\n"
        '\trows, _ := db.QueryContext(ctx, "SELECT * FROM users WHERE id = $1", id)\n'
        '\texec.CommandContext(ctx, "ping", "-c", "1", host)\n'
        "\tcfg := &tls.Config{InsecureSkipVerify: false}\n"
        "\ttokenBytes := make([]byte, 32)\n"
        "\trand.Read(tokenBytes)\n"
        '\tsigned, _ := jwtToken.SignedString([]byte(os.Getenv("JWT_SECRET")))\n'
        "\t_, _, _, _ = rows, cfg, tokenBytes, signed\n"
        "}\n",
        encoding="utf-8",
    )
    assert not {
        f["rule_id"]
        for f in _scan_file(safe, tmp_path)
        if f["rule_id"].startswith("go-")
    }


def test_go_rules_do_not_fire_outside_go_files(tmp_path):
    lookalike = tmp_path / "snippets.py"
    lookalike.write_text(
        'SNIPPET = """\n'
        'db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))\n'
        'exec.Command("sh", "-c", userCmd)\n'
        "tls.Config{InsecureSkipVerify: true}\n"
        '_ "net/http/pprof"\n'
        '"""\n',
        encoding="utf-8",
    )
    assert not {
        f["rule_id"]
        for f in _scan_file(lookalike, tmp_path)
        if f["rule_id"].startswith("go-")
    }
