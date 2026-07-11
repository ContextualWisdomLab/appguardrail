"""Coverage tests for the C# / ASP.NET (dotnet.yml) rule pack."""

from scanner.cli.appguardrail import SCAN_RULES, _path_allowed_by_rule, _scan_file

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], []).append(_r)


def _rules(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


def _search(rule_id, text):
    return any(r["pattern"].search(text) for r in _rules(rule_id))


# ---------------------------------------------------------------------------
# dotnet-sql-injection-concat
# ---------------------------------------------------------------------------


def test_dotnet_sql_injection_concat_positive():
    for r in _rules("dotnet-sql-injection-concat"):
        assert r["severity"] == "CRITICAL"
    assert _search(
        "dotnet-sql-injection-concat",
        'var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = \'" + name + "\'", conn);',
    )
    assert _search(
        "dotnet-sql-injection-concat",
        'context.Database.ExecuteSqlRaw($"DELETE FROM Orders WHERE Id = {orderId}");',
    )
    assert _search(
        "dotnet-sql-injection-concat",
        'db.Users.FromSqlRaw($@"SELECT * FROM Users WHERE Id = {id}");',
    )
    assert _search(
        "dotnet-sql-injection-concat",
        'await context.Database.ExecuteSqlRawAsync("UPDATE T SET X = " + value);',
    )


def test_dotnet_sql_injection_concat_negative():
    # Parameterized query: safe.
    assert not _search(
        "dotnet-sql-injection-concat",
        'var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn);',
    )
    # EF Core interpolated APIs parameterize their arguments: safe.
    assert not _search(
        "dotnet-sql-injection-concat",
        'context.Database.ExecuteSqlInterpolated($"DELETE FROM Orders WHERE Id = {orderId}");',
    )
    assert not _search(
        "dotnet-sql-injection-concat",
        'db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Id = {id}");',
    )


# ---------------------------------------------------------------------------
# dotnet-binaryformatter-deserialize
# ---------------------------------------------------------------------------


def test_dotnet_binaryformatter_positive():
    for r in _rules("dotnet-binaryformatter-deserialize"):
        assert r["severity"] == "CRITICAL"
    assert _search(
        "dotnet-binaryformatter-deserialize",
        "var formatter = new BinaryFormatter();",
    )
    assert _search(
        "dotnet-binaryformatter-deserialize",
        "var obj = new LosFormatter().Deserialize(payload);",
    )
    assert _search(
        "dotnet-binaryformatter-deserialize",
        "var s = new NetDataContractSerializer();",
    )


def test_dotnet_binaryformatter_negative():
    assert not _search(
        "dotnet-binaryformatter-deserialize",
        "var json = JsonSerializer.Deserialize<Order>(body);",
    )
    assert not _search(
        "dotnet-binaryformatter-deserialize",
        "var xml = new XmlSerializer(typeof(Order));",
    )
    # Similarly-prefixed identifier must not match.
    assert not _search(
        "dotnet-binaryformatter-deserialize",
        "var s = new BinaryFormatterSettings();",
    )


# ---------------------------------------------------------------------------
# dotnet-process-start-user-input
# ---------------------------------------------------------------------------


def test_dotnet_process_start_positive():
    for r in _rules("dotnet-process-start-user-input"):
        assert r["severity"] == "CRITICAL"
    assert _search(
        "dotnet-process-start-user-input",
        'Process.Start("cmd.exe", "/c ping " + host);',
    )
    assert _search(
        "dotnet-process-start-user-input",
        'Process.Start($"/usr/bin/{tool}");',
    )
    assert _search(
        "dotnet-process-start-user-input",
        'var psi = new ProcessStartInfo("bash", "-c " + userScript);',
    )
    assert _search(
        "dotnet-process-start-user-input",
        'psi.Arguments = $"/c del {fileName}";',
    )


def test_dotnet_process_start_negative():
    assert not _search(
        "dotnet-process-start-user-input",
        'Process.Start("notepad.exe");',
    )
    assert not _search(
        "dotnet-process-start-user-input",
        "Process.Start(startInfo);",
    )
    assert not _search(
        "dotnet-process-start-user-input",
        'psi.Arguments = "/c dir";',
    )


# ---------------------------------------------------------------------------
# aspnet-request-validation-disabled
# ---------------------------------------------------------------------------


def test_aspnet_request_validation_disabled_positive():
    for r in _rules("aspnet-request-validation-disabled"):
        assert r["severity"] == "HIGH"
    assert _search(
        "aspnet-request-validation-disabled",
        '<%@ Page Language="C#" ValidateRequest="false" %>',
    )
    assert _search(
        "aspnet-request-validation-disabled",
        "[ValidateInput(false)]\npublic ActionResult Save(string html)",
    )
    assert _search(
        "aspnet-request-validation-disabled",
        '<pages validateRequest="false" />',
    )


def test_aspnet_request_validation_disabled_negative():
    assert not _search(
        "aspnet-request-validation-disabled",
        '<%@ Page Language="C#" ValidateRequest="true" %>',
    )
    assert not _search(
        "aspnet-request-validation-disabled",
        "[ValidateInput(true)]\npublic ActionResult Save(string html)",
    )


# ---------------------------------------------------------------------------
# dotnet-cookie-secure-false
# ---------------------------------------------------------------------------


def test_dotnet_cookie_secure_false_positive():
    for r in _rules("dotnet-cookie-secure-false"):
        assert r["severity"] == "HIGH"
    assert _search(
        "dotnet-cookie-secure-false",
        "options.Cookie.SecurePolicy = CookieSecurePolicy.None;",
    )
    assert _search(
        "dotnet-cookie-secure-false",
        "Response.Cookies.Append(name, value, new CookieOptions { Secure = false });",
    )
    assert _search(
        "dotnet-cookie-secure-false",
        '<httpCookies requireSSL="false" />',
    )


def test_dotnet_cookie_secure_false_negative():
    assert not _search(
        "dotnet-cookie-secure-false",
        "options.Cookie.SecurePolicy = CookieSecurePolicy.Always;",
    )
    assert not _search(
        "dotnet-cookie-secure-false",
        "new CookieOptions { Secure = true, HttpOnly = true };",
    )
    # Different property names must not match (\b boundary).
    assert not _search(
        "dotnet-cookie-secure-false",
        "IsSecure = false;",
    )


# ---------------------------------------------------------------------------
# appsettings-connectionstring-password
# ---------------------------------------------------------------------------

# Assembled at runtime so no secret-shaped literal is committed.
_LITERAL_PASSWORD = "hun" + "ter" + "2"


def test_appsettings_connectionstring_password_positive():
    for r in _rules("appsettings-connectionstring-password"):
        assert r["severity"] == "HIGH"
    conn = (
        '"DefaultConnection": "Server=db;Database=app;User Id=sa;Password='
        + _LITERAL_PASSWORD
        + ';"'
    )
    assert _search("appsettings-connectionstring-password", conn)
    web_config = (
        'connectionString="Data Source=.;Initial Catalog=app;Pwd='
        + _LITERAL_PASSWORD
        + ';"'
    )
    assert _search("appsettings-connectionstring-password", web_config)


def test_appsettings_connectionstring_password_negative():
    # Placeholder / templated values are not literal secrets.
    assert not _search(
        "appsettings-connectionstring-password",
        '"DefaultConnection": "Server=db;Database=app;Password=${DB_PASSWORD};"',
    )
    assert not _search(
        "appsettings-connectionstring-password",
        '"DefaultConnection": "Server=db;Database=app;Password={0};"',
    )
    assert not _search(
        "appsettings-connectionstring-password",
        '"DefaultConnection": "Server=db;Database=app;Password=%DB_PASS%;"',
    )
    # Integrated security, no password at all.
    assert not _search(
        "appsettings-connectionstring-password",
        '"DefaultConnection": "Server=db;Database=app;Integrated Security=true;"',
    )


# ---------------------------------------------------------------------------
# Path scoping
# ---------------------------------------------------------------------------


def test_dotnet_rules_are_path_scoped_to_dotnet_files():
    for rule in _rules("dotnet-sql-injection-concat"):
        include = rule["include_paths"]
        assert "**/*.cs" in include
        assert _path_allowed_by_rule("src/Data/Repo.cs", include, [])
        assert _path_allowed_by_rule("Program.cs", include, [])
        assert not _path_allowed_by_rule("src/data/repo.py", include, [])
        assert not _path_allowed_by_rule("src/query.ts", include, [])

    for rule in _rules("appsettings-connectionstring-password"):
        include = rule["include_paths"]
        assert _path_allowed_by_rule("appsettings.json", include, [])
        assert _path_allowed_by_rule("src/Api/appsettings.Development.json", include, [])
        assert _path_allowed_by_rule("legacy/web.config", include, [])
        assert not _path_allowed_by_rule("package.json", include, [])


# ---------------------------------------------------------------------------
# End-to-end through the scanner
# ---------------------------------------------------------------------------


def test_scan_file_detects_dotnet_rules_end_to_end(tmp_path):
    cs_file = tmp_path / "OrdersController.cs"
    cs_file.write_text(
        'var cmd = new SqlCommand("SELECT * FROM Orders WHERE Id = " + id, conn);\n'
        "var formatter = new BinaryFormatter();\n"
        'Process.Start("cmd.exe", "/c ping " + host);\n'
        "options.Cookie.SecurePolicy = CookieSecurePolicy.None;\n",
        encoding="utf-8",
    )
    rule_ids = {finding["rule_id"] for finding in _scan_file(cs_file, tmp_path)}
    assert "dotnet-sql-injection-concat" in rule_ids
    assert "dotnet-binaryformatter-deserialize" in rule_ids
    assert "dotnet-process-start-user-input" in rule_ids
    assert "dotnet-cookie-secure-false" in rule_ids


def test_scan_file_detects_appsettings_password_end_to_end(tmp_path):
    settings = tmp_path / "appsettings.json"
    settings.write_text(
        "{\n"
        '  "ConnectionStrings": {\n'
        '    "Default": "Server=db;Database=app;User Id=sa;Password='
        + _LITERAL_PASSWORD
        + ';"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = [
        finding
        for finding in _scan_file(settings, tmp_path)
        if finding["rule_id"] == "appsettings-connectionstring-password"
    ]
    assert findings
    assert findings[0]["severity"] == "HIGH"
    # Rule id contains "password", so the snippet must be redacted.
    assert _LITERAL_PASSWORD not in findings[0]["snippet"]


def test_dotnet_rules_do_not_fire_outside_dotnet_paths(tmp_path):
    py_file = tmp_path / "runner.py"
    py_file.write_text(
        '# new SqlCommand("SELECT * FROM Orders WHERE Id = " + id, conn)\n'
        "# var formatter = new BinaryFormatter()\n",
        encoding="utf-8",
    )
    rule_ids = {finding["rule_id"] for finding in _scan_file(py_file, tmp_path)}
    assert "dotnet-sql-injection-concat" not in rule_ids
    assert "dotnet-binaryformatter-deserialize" not in rule_ids
