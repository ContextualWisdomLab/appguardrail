"""Coverage tests for the injection + Anthropic-key detection rules."""

from scanner.cli.appguardrail import SCAN_RULES

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], _r)


def _rule(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


def test_sql_injection_raw_unsafe():
    r = _rule("sql-injection-raw-unsafe")
    assert r["severity"] == "CRITICAL"
    assert r["pattern"].search("prisma.$queryRawUnsafe(`SELECT ${id}`)")
    assert r["pattern"].search("db.$executeRawUnsafe(sql)")
    # the safe parameterizing tagged-template must NOT match
    assert not r["pattern"].search("prisma.$queryRaw`SELECT 1`")


def test_react_dangerously_set_inner_html():
    r = _rule("react-dangerously-set-inner-html")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search("<div dangerouslySetInnerHTML={{__html: bio}} />")
    assert not r["pattern"].search("element.textContent = bio")


def test_hardcoded_anthropic_api_key():
    r = _rule("hardcoded-anthropic-api-key")
    assert r["severity"] == "CRITICAL"
    assert r["pattern"].search("key = 'sk-ant-api03-AbCdEf0123456789xyzXYZ_-abc'")
    assert not r["pattern"].search("key = 'sk-ant-'")  # too short
    assert not r["pattern"].search("token = 'sk-live-notananthropickey'")


def _python_command_matches(source):
    rule = _rule("python-command-injection")
    return list(rule["finder"](source))


def test_python_command_injection():
    rule = _rule("python-command-injection")
    assert rule["severity"] == "CRITICAL"

    source = """os.system(user_input)
subprocess.run(build_command(user_input), shell=True)
subprocess.Popen(command, shell = 1)
subprocess.call(command, shell=enabled)
"""
    matches = _python_command_matches(source)
    assert len(matches) == 4
    assert [source.count("\n", 0, match.start()) + 1 for match in matches] == [
        1,
        2,
        3,
        4,
    ]


def test_python_command_injection_ignores_non_calls_comments_and_strings():
    source = """# os.system(user_input)
warning = "subprocess.run(command, shell=True)"
os.system = replacement
subprocess.run(["ls", "-l"])
subprocess.Popen(["ls", "-l"], shell=False)
subprocess.call(command, shell=0)
subprocess.check_output(command, shell=None)
"""
    assert _python_command_matches(source) == []


def test_python_command_injection_preserves_non_ascii_source_offset():
    source = "label = '한글'; os.system(command)\n"
    match = _python_command_matches(source)[0]
    assert source[match.start() :].startswith("os.system")


def test_python_command_injection_falls_back_for_invalid_python():
    matches = _python_command_matches("if (\n    os.system(user_input)\n")
    assert len(matches) == 1
