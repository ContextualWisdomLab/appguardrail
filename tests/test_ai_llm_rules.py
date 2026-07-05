"""Coverage tests for the AI/LLM-specific detection rules (ai-llm.yml)."""

import pytest

from scanner.cli.appguardrail import SCAN_RULES

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], _r)


def _rule(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


CASES = {
    "langchain-allow-dangerous-flags": (
        ["FAISS.load_local('i', e, allow_dangerous_deserialization=True)",
         "create_pandas_dataframe_agent(llm, df, allow_dangerous_code=True)"],
        ["load_local('i', e, allow_dangerous_deserialization=False)",
         "safe_deserialization=True"],
    ),
    "langchain-llm-code-execution-tool": (
        ["tool = PythonREPLTool()", "load_tools(['python_repl'], llm=llm)"],
        ["PythonHelper()", "load_tools(['serpapi'], llm=llm)"],
    ),
    "prompt-injection-user-input-python": (
        ['prompt = f"Answer this: {user_input}"',
         'messages = f"reply to {request.json}"'],
        ['prompt = f"Answer about {topic}"', 'prompt = "static text"'],
    ),
    "prompt-injection-user-input-js": (
        ["const prompt = `ask: ${req.body.message}`",
         "const systemPrompt = `ctx ${userInput}`"],
        ["const prompt = `hi ${name}`", "const prompt = 'static'"],
    ),
    "hardcoded-ai-provider-key": (
        ["key = 'hf_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab'",
         "k = 'xai-ABCDEFGHIJKLMNOPQRSTUVWX'"],
        ["k = 'hf_short'", "token = os.environ['HF_TOKEN']"],
    ),
    "llm-response-to-code-execution": (
        ["exec(response.choices[0].message.content)",
         "eval(resp.choices[0].text)"],
        ["print(response.choices[0].message.content)",
         "x = response.choices[0].message.content"],
    ),
}


@pytest.mark.parametrize("rule_id", CASES.keys())
def test_ai_rule_precision(rule_id):
    rule = _rule(rule_id)
    positives, negatives = CASES[rule_id]
    for s in positives:
        assert rule["pattern"].search(s), f"{rule_id} should match: {s!r}"
    for s in negatives:
        assert not rule["pattern"].search(s), f"{rule_id} false-positive on: {s!r}"


def test_ai_rule_severities():
    assert _rule("langchain-allow-dangerous-flags")["severity"] == "CRITICAL"
    assert _rule("llm-response-to-code-execution")["severity"] == "CRITICAL"
    assert _rule("prompt-injection-user-input-python")["severity"] == "HIGH"
