"""Coverage tests for the Terraform / IaC misconfiguration rules."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], _r)


def _rule(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


def test_s3_bucket_public_acl():
    r = _rule("terraform-s3-bucket-public-acl")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search('acl = "public-read"')
    assert r["pattern"].search('  acl = "public-read-write"')
    # restricted / private ACLs must not match
    assert not r["pattern"].search('acl = "private"')
    assert not r["pattern"].search('acl = "authenticated-read"')


def test_security_group_open_to_world():
    r = _rule("terraform-security-group-open-to-world")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search('cidr_blocks = ["0.0.0.0/0"]')
    assert r["pattern"].search('cidr_blocks = [\n    "0.0.0.0/0"\n  ]')
    # restricted CIDR ranges must not match
    assert not r["pattern"].search('cidr_blocks = ["10.0.0.0/16"]')
    assert not r["pattern"].search('cidr_blocks = ["192.168.1.0/24"]')


def test_unencrypted_storage():
    r = _rule("terraform-unencrypted-storage")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search("encrypted = false")
    assert r["pattern"].search("  encrypted   = false")
    # encryption enabled must not match
    assert not r["pattern"].search("encrypted = true")
    assert not r["pattern"].search("encrypted = var.encrypt_at_rest")


def test_rds_publicly_accessible():
    r = _rule("terraform-rds-publicly-accessible")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search("publicly_accessible = true")
    assert r["pattern"].search("  publicly_accessible   = true")
    # not publicly accessible must not match
    assert not r["pattern"].search("publicly_accessible = false")
    assert not r["pattern"].search("publicly_accessible = var.expose_db")


def test_hardcoded_secret():
    r = _rule("terraform-hardcoded-secret")
    assert r["severity"] == "CRITICAL"
    assert r["pattern"].search('password = "Sup3rSecretHardcoded!"')
    assert r["pattern"].search('secret_key = "AKIAIOSFODNN7EXAMPLEKEY"')
    # variable / data references and interpolations must not match
    assert not r["pattern"].search("password = var.db_password")
    assert not r["pattern"].search('secret_key = "${var.secret}"')
    assert not r["pattern"].search("access_key = data.aws_ssm_parameter.key.value")


def test_terraform_rules_end_to_end(tmp_path):
    """Confirm rules actually fire end-to-end on real .tf files."""
    positive = tmp_path / "insecure.tf"
    positive.write_text(
        'resource "aws_s3_bucket_acl" "b" {\n'
        '  acl = "public-read-write"\n'
        "}\n"
        'resource "aws_security_group" "sg" {\n'
        "  ingress {\n"
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n"
        'resource "aws_ebs_volume" "v" {\n'
        "  encrypted = false\n"
        "}\n"
        'resource "aws_db_instance" "db" {\n'
        "  publicly_accessible = true\n"
        '  password            = "Sup3rSecretHardcoded!"\n'
        "}\n"
    )
    findings = _scan_file(positive, tmp_path)
    fired = {f["rule_id"] for f in findings}
    for rule_id in (
        "terraform-s3-bucket-public-acl",
        "terraform-security-group-open-to-world",
        "terraform-unencrypted-storage",
        "terraform-rds-publicly-accessible",
        "terraform-hardcoded-secret",
    ):
        assert rule_id in fired, f"expected {rule_id} to fire on insecure.tf"

    negative = tmp_path / "secure.tf"
    negative.write_text(
        'resource "aws_s3_bucket_acl" "b" {\n'
        '  acl = "private"\n'
        "}\n"
        'resource "aws_security_group" "sg" {\n'
        "  ingress {\n"
        '    cidr_blocks = ["10.0.0.0/16"]\n'
        "  }\n"
        "}\n"
        'resource "aws_ebs_volume" "v" {\n'
        "  encrypted = true\n"
        "}\n"
        'resource "aws_db_instance" "db" {\n'
        "  publicly_accessible = false\n"
        "  password            = var.db_password\n"
        '  secret_key          = "${var.secret}"\n'
        "}\n"
    )
    negative_findings = [
        f for f in _scan_file(negative, tmp_path) if f["rule_id"].startswith("terraform-")
    ]
    assert negative_findings == [], negative_findings
