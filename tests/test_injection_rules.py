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
