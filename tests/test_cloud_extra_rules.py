"""Coverage tests for the additional-cloud IaC misconfiguration rule pack.

Covers DigitalOcean, Oracle Cloud (OCI) and Alibaba Cloud Terraform rules
defined in scanner/rules/cloud-extra.yml. Each test asserts severity plus at
least two positive matches and two negatives, and one end-to-end scan confirms
the pack fires through the real file scanner and stays quiet on safe config.
"""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], _r)


def _rule(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


def test_digitalocean_firewall_sensitive_port_world_open():
    r = _rule("digitalocean-firewall-sensitive-port-world-open")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search(
        'port_range = "22"\n    source_addresses = ["0.0.0.0/0"]'
    )
    assert r["pattern"].search(
        'port_range = "5432"\n    source_addresses = ["203.0.113.4", "0.0.0.0/0"]'
    )
    # Public web port is legitimate.
    assert not r["pattern"].search(
        'port_range = "443"\n    source_addresses = ["0.0.0.0/0"]'
    )
    # SSH restricted to a private range is fine.
    assert not r["pattern"].search(
        'port_range = "22"\n    source_addresses = ["10.0.0.0/8"]'
    )


def test_digitalocean_spaces_bucket_public_acl():
    r = _rule("digitalocean-spaces-bucket-public-acl")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search(
        'resource "digitalocean_spaces_bucket" "s" {\n  acl = "public-read"\n}'
    )
    assert r["pattern"].search(
        'resource "digitalocean_spaces_bucket" "s" {\n  acl = "public-read-write"\n}'
    )
    assert not r["pattern"].search(
        'resource "digitalocean_spaces_bucket" "s" {\n  acl = "private"\n}'
    )
    # A non-DigitalOcean bucket with a public ACL must not match.
    assert not r["pattern"].search(
        'resource "aws_s3_bucket" "s" {\n  acl = "public-read"\n}'
    )


def test_oracle_security_list_ingress_world_open():
    r = _rule("oracle-security-list-ingress-world-open")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search(
        'ingress_security_rules {\n    protocol = "6"\n    source = "0.0.0.0/0"\n  }'
    )
    assert r["pattern"].search('ingress_security_rules {\n source = "0.0.0.0/0" }')
    assert not r["pattern"].search(
        'ingress_security_rules {\n    source = "10.0.0.0/16"\n  }'
    )
    # AWS-style world-open ingress uses a different attribute and must not match.
    assert not r["pattern"].search('cidr_blocks = ["0.0.0.0/0"]')


def test_oracle_object_storage_bucket_public():
    r = _rule("oracle-object-storage-bucket-public")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search(
        'resource "oci_objectstorage_bucket" "b" {\n  access_type = "ObjectRead"\n}'
    )
    assert r["pattern"].search(
        'resource "oci_objectstorage_bucket" "b" {\n'
        '  access_type = "ObjectReadWithoutList"\n}'
    )
    assert not r["pattern"].search(
        'resource "oci_objectstorage_bucket" "b" {\n'
        '  access_type = "NoPublicAccess"\n}'
    )
    assert not r["pattern"].search('access_type = "ObjectRead"')  # no OCI resource


def test_alibaba_security_group_rule_world_open():
    r = _rule("alibaba-security-group-rule-world-open")
    assert r["severity"] == "HIGH"
    assert r["pattern"].search(
        'resource "alicloud_security_group_rule" "r" {\n  cidr_ip = "0.0.0.0/0"\n}'
    )
    assert r["pattern"].search(
        'resource "alicloud_security_group_rule" "r" {\n'
        '  type = "ingress"\n  cidr_ip = "0.0.0.0/0"\n}'
    )
    assert not r["pattern"].search(
        'resource "alicloud_security_group_rule" "r" {\n'
        '  cidr_ip = "172.16.0.0/12"\n}'
    )
    # cidr_ip alone (no Alibaba resource) must not match.
    assert not r["pattern"].search('cidr_ip = "0.0.0.0/0"')


def test_alibaba_oss_bucket_public_write():
    r = _rule("alibaba-oss-bucket-public-write")
    assert r["severity"] == "CRITICAL"
    assert r["pattern"].search(
        'resource "alicloud_oss_bucket" "b" {\n  acl = "public-read-write"\n}'
    )
    assert r["pattern"].search(
        'resource "alicloud_oss_bucket" "b" {\n  bucket = "x"\n'
        '  acl = "public-read-write"\n}'
    )
    assert not r["pattern"].search(
        'resource "alicloud_oss_bucket" "b" {\n  acl = "private"\n}'
    )
    # Read-only public is handled elsewhere; this critical rule targets write.
    assert not r["pattern"].search(
        'resource "alicloud_oss_bucket" "b" {\n  acl = "public-read"\n}'
    )


def test_cloud_extra_end_to_end_scan(tmp_path):
    """The pack must fire through the real scanner on a .tf file."""
    bad = tmp_path / "insecure.tf"
    bad.write_text(
        'resource "digitalocean_firewall" "web" {\n'
        "  inbound_rule {\n"
        '    port_range       = "22"\n'
        '    source_addresses = ["0.0.0.0/0"]\n'
        "  }\n}\n\n"
        'resource "oci_objectstorage_bucket" "pub" {\n'
        '  access_type = "ObjectRead"\n}\n\n'
        'resource "alicloud_oss_bucket" "b" {\n'
        '  acl = "public-read-write"\n}\n',
        encoding="utf-8",
    )
    findings = _scan_file(bad, tmp_path)
    fired = {f["rule_id"] for f in findings}
    assert "digitalocean-firewall-sensitive-port-world-open" in fired
    assert "oracle-object-storage-bucket-public" in fired
    assert "alibaba-oss-bucket-public-write" in fired

    good = tmp_path / "secure.tf"
    good.write_text(
        'resource "digitalocean_firewall" "web" {\n'
        "  inbound_rule {\n"
        '    port_range       = "443"\n'
        '    source_addresses = ["0.0.0.0/0"]\n'
        "  }\n}\n\n"
        'resource "alicloud_oss_bucket" "b" {\n  acl = "private"\n}\n',
        encoding="utf-8",
    )
    good_findings = {
        f["rule_id"]
        for f in _scan_file(good, tmp_path)
        if f["rule_id"].startswith(("digitalocean-", "oracle-", "alibaba-"))
    }
    assert good_findings == set()
