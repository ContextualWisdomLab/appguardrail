"""Coverage tests for the Azure (ARM/Bicep/Terraform-azurerm) rule pack."""

from scanner.cli.appguardrail import SCAN_RULES

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], []).append(_r)


def _rules(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


def _matches(rule_id, text):
    return any(r["pattern"].search(text) for r in _rules(rule_id))


def _severity(rule_id):
    severities = {r["severity"] for r in _rules(rule_id)}
    assert len(severities) == 1
    return severities.pop()


def test_azure_rules_apply_to_all_file_types():
    # languages: [generic] -> extensions is None -> .tf/.bicep/.json all scanned
    for rule_id in (
        "azure-storage-blob-public-access",
        "azure-nsg-rule-open-to-internet",
        "azure-sql-firewall-open-to-all-ips",
        "azure-storage-https-only-disabled",
        "azure-key-vault-purge-protection-disabled",
    ):
        for r in _rules(rule_id):
            assert r["extensions"] is None


def test_azure_storage_blob_public_access():
    rid = "azure-storage-blob-public-access"
    assert _severity(rid) == "HIGH"
    # positives: Terraform + ARM/Bicep spellings
    assert _matches(rid, 'allow_blob_public_access = true')
    assert _matches(rid, '"allowBlobPublicAccess": true')
    assert _matches(rid, "allowBlobPublicAccess: true")
    # negatives: disabled access must not match
    assert not _matches(rid, "allow_blob_public_access = false")
    assert not _matches(rid, '"allowBlobPublicAccess": false')


def test_azure_nsg_rule_open_to_internet():
    rid = "azure-nsg-rule-open-to-internet"
    assert _severity(rid) == "CRITICAL"
    # positives: wildcard, Internet service tag, 0.0.0.0/0 in tf + ARM/Bicep
    assert _matches(rid, 'source_address_prefix = "*"')
    assert _matches(rid, 'source_address_prefix = "Internet"')
    assert _matches(rid, '"sourceAddressPrefix": "0.0.0.0/0"')
    assert _matches(rid, "sourceAddressPrefix: '*'")
    # negatives: scoped CIDR ranges and service tags stay quiet
    assert not _matches(rid, 'source_address_prefix = "10.0.0.0/16"')
    assert not _matches(rid, '"sourceAddressPrefix": "AzureLoadBalancer"')


def test_azure_sql_firewall_open_to_all_ips():
    rid = "azure-sql-firewall-open-to-all-ips"
    assert _severity(rid) == "CRITICAL"
    # positives
    assert _matches(rid, 'end_ip_address = "255.255.255.255"')
    assert _matches(rid, '"endIpAddress": "255.255.255.255"')
    assert _matches(rid, "endIpAddress: '255.255.255.255'")
    # negatives: the 0.0.0.0-0.0.0.0 "Azure services" rule and scoped ranges
    assert not _matches(rid, 'end_ip_address = "0.0.0.0"')
    assert not _matches(rid, '"endIpAddress": "203.0.113.42"')


def test_azure_storage_https_only_disabled():
    rid = "azure-storage-https-only-disabled"
    assert _severity(rid) == "HIGH"
    # positives: legacy + current azurerm attribute names, ARM/Bicep property
    assert _matches(rid, "enable_https_traffic_only = false")
    assert _matches(rid, "https_traffic_only_enabled = false")
    assert _matches(rid, '"supportsHttpsTrafficOnly": false')
    # negatives
    assert not _matches(rid, "enable_https_traffic_only = true")
    assert not _matches(rid, '"supportsHttpsTrafficOnly": true')


def test_azure_key_vault_purge_protection_disabled():
    rid = "azure-key-vault-purge-protection-disabled"
    assert _severity(rid) == "HIGH"
    # positives
    assert _matches(rid, "purge_protection_enabled = false")
    assert _matches(rid, '"enablePurgeProtection": false')
    assert _matches(rid, "enablePurgeProtection: false")
    # negatives
    assert not _matches(rid, "purge_protection_enabled = true")
    assert not _matches(rid, '"enablePurgeProtection": true')
