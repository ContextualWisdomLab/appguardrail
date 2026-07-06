"""Coverage tests for the Serverless Framework / AWS SAM misconfiguration rules.

Each rule is high precision and scoped (via YAML `paths.include`) to
serverless.yml / template.yaml files. These tests exercise the compiled
regexes directly plus one end-to-end scan that confirms path scoping.
"""

import json
import subprocess
import sys

from scanner.cli.appguardrail import SCAN_RULES

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], _r)


def _rule(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


def test_all_serverless_rules_loaded():
    for rid in (
        "serverless-lambda-iam-wildcard",
        "serverless-admin-managed-policy",
        "serverless-function-url-auth-none",
        "serverless-plaintext-secret-env",
        "serverless-http-cors-wildcard",
    ):
        r = _rule(rid)
        # Every serverless rule is scoped to serverless/SAM config files only.
        assert r["include_paths"], f"{rid} must be path-scoped"
        assert any("serverless" in p for p in r["include_paths"])


def test_lambda_iam_wildcard():
    r = _rule("serverless-lambda-iam-wildcard")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search("    Action: '*'")
    assert r["pattern"].search('  - Resource: "*"')
    # scoped, least-privilege statements must NOT match
    assert not r["pattern"].search("    Action: 's3:GetObject'")
    assert not r["pattern"].search("    Resource: 'arn:aws:s3:::bucket/*'")


def test_admin_managed_policy():
    r = _rule("serverless-admin-managed-policy")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search("- arn:aws:iam::aws:policy/AdministratorAccess")
    assert r["pattern"].search("    Policies: AdministratorAccess")
    # a scoped managed policy must NOT match
    assert not r["pattern"].search("    Policies: AmazonS3ReadOnlyAccess")
    assert not r["pattern"].search(
        "- arn:aws:iam::aws:policy/ReadOnlyAccess"
    )


def test_function_url_auth_none():
    r = _rule("serverless-function-url-auth-none")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search("      AuthType: NONE")
    assert r["pattern"].search("  AuthType: 'NONE'")
    # IAM-protected URLs and similarly-named values must NOT match
    assert not r["pattern"].search("      AuthType: AWS_IAM")
    assert not r["pattern"].search("      AuthType: NONESUCH_x")


def test_plaintext_secret_env():
    r = _rule("serverless-plaintext-secret-env")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search("    DB_PASSWORD: supersecret123")
    assert r["pattern"].search("    API_KEY: 'abcd1234efgh'")
    # references to a secret store must NOT match
    assert not r["pattern"].search("    DB_PASSWORD: ${ssm:/app/db-password}")
    assert not r["pattern"].search("    API_KEY: '${env:API_KEY}'")
    assert not r["pattern"].search("    REGION: us-east-1")


def test_http_cors_wildcard():
    r = _rule("serverless-http-cors-wildcard")
    assert r["severity"] == "WARNING"
    assert r["pattern"].search("      cors: true")
    assert r["pattern"].search("      cors: '*'")
    # an explicit trusted origin must NOT match
    assert not r["pattern"].search("      cors: false")
    assert not r["pattern"].search("      cors: 'https://example.com'")


def test_end_to_end_scan_and_path_scoping(tmp_path):
    """A real scan fires on serverless.yml but not on look-alike YAML."""
    (tmp_path / "serverless.yml").write_text(
        "provider:\n"
        "  iamRoleStatements:\n"
        "    - Effect: Allow\n"
        "      Action: '*'\n"
        "  environment:\n"
        "    DB_PASSWORD: supersecret123\n"
        "functions:\n"
        "  hello:\n"
        "    events:\n"
        "      - http:\n"
        "          cors: true\n",
        encoding="utf-8",
    )
    # Same tokens, but not a serverless/SAM file -> path scoping suppresses it.
    (tmp_path / "random.yml").write_text(
        "Action: '*'\ncors: true\nDB_PASSWORD: hunter2plaintext\n",
        encoding="utf-8",
    )
    out = tmp_path / "out.json"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "scanner.cli.appguardrail",
            "scan",
            str(tmp_path),
            "--findings-json",
            str(out),
        ],
        check=False,
        capture_output=True,
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    findings = data["findings"] if isinstance(data, dict) else data
    serverless = [
        f
        for f in findings
        if str(f.get("rule_id") or f.get("id")).startswith("serverless-")
    ]
    fired_ids = {f.get("rule_id") or f.get("id") for f in serverless}
    assert "serverless-lambda-iam-wildcard" in fired_ids
    assert "serverless-plaintext-secret-env" in fired_ids
    assert "serverless-http-cors-wildcard" in fired_ids
    # Every serverless finding must come from the real serverless.yml.
    for f in serverless:
        path = str(f.get("path") or f.get("file") or "")
        assert path.endswith("serverless.yml"), f"leaked onto {path}"
