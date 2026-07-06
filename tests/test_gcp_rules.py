"""Coverage tests for the Google Cloud (Terraform/gcloud) misconfiguration rules."""

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], []).append(_r)


def _rules(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


def _matches(rule_id, text):
    return any(r["pattern"].search(text) for r in _rules(rule_id))


def test_gcp_iam_public_member():
    for r in _rules("gcp-iam-public-member"):
        assert r["severity"] == "CRITICAL"
    # Terraform single member
    assert _matches(
        "gcp-iam-public-member",
        'resource "google_storage_bucket_iam_member" "pub" {\n'
        '  role   = "roles/storage.objectViewer"\n'
        '  member = "allUsers"\n'
        "}\n",
    )
    # Terraform members list, entry on a later line
    assert _matches(
        "gcp-iam-public-member",
        'members = [\n  "serviceAccount:app@p.iam.gserviceaccount.com",\n'
        '  "allAuthenticatedUsers",\n]\n',
    )
    # gcloud CLI binding
    assert _matches(
        "gcp-iam-public-member",
        "gcloud run services add-iam-policy-binding api "
        '--member="allUsers" --role="roles/run.invoker"',
    )
    # Scoped members must NOT match
    assert not _matches(
        "gcp-iam-public-member",
        'member = "serviceAccount:app@p.iam.gserviceaccount.com"',
    )
    assert not _matches(
        "gcp-iam-public-member",
        'members = ["user:alice@example.com", "group:eng@example.com"]',
    )
    assert not _matches(
        "gcp-iam-public-member",
        "gcloud projects add-iam-policy-binding p "
        '--member="user:alice@example.com" --role="roles/viewer"',
    )


def test_gcp_firewall_open_to_world():
    for r in _rules("gcp-firewall-open-to-world"):
        assert r["severity"] == "HIGH"
    assert _matches(
        "gcp-firewall-open-to-world",
        'source_ranges = ["0.0.0.0/0"]',
    )
    # 0.0.0.0/0 as a later list element
    assert _matches(
        "gcp-firewall-open-to-world",
        'source_ranges = [\n  "10.0.0.0/8",\n  "0.0.0.0/0",\n]',
    )
    assert _matches(
        "gcp-firewall-open-to-world",
        "gcloud compute firewall-rules create allow-ssh "
        "--allow tcp:22 --source-ranges=0.0.0.0/0",
    )
    # Restricted ranges must NOT match
    assert not _matches(
        "gcp-firewall-open-to-world",
        'source_ranges = ["10.0.0.0/8", "35.235.240.0/20"]',
    )
    assert not _matches(
        "gcp-firewall-open-to-world",
        "gcloud compute firewall-rules create allow-iap "
        "--allow tcp:22 --source-ranges=35.235.240.0/20",
    )


def test_gcp_sql_public_authorized_network():
    for r in _rules("gcp-sql-public-authorized-network"):
        assert r["severity"] == "CRITICAL"
    assert _matches(
        "gcp-sql-public-authorized-network",
        "ip_configuration {\n  authorized_networks {\n"
        '    name  = "everyone"\n    value = "0.0.0.0/0"\n  }\n}\n',
    )
    assert _matches(
        "gcp-sql-public-authorized-network",
        'authorized_networks { value = "0.0.0.0/0" }',
    )
    # Restricted network must NOT match
    assert not _matches(
        "gcp-sql-public-authorized-network",
        "authorized_networks {\n"
        '  name  = "office"\n  value = "203.0.113.0/24"\n}\n',
    )
    # 0.0.0.0/0 outside an authorized_networks block must NOT match
    assert not _matches(
        "gcp-sql-public-authorized-network",
        'value = "0.0.0.0/0"',
    )


def test_gcp_gke_legacy_abac_enabled():
    for r in _rules("gcp-gke-legacy-abac-enabled"):
        assert r["severity"] == "HIGH"
    assert _matches("gcp-gke-legacy-abac-enabled", "enable_legacy_abac = true")
    assert _matches("gcp-gke-legacy-abac-enabled", "enable_legacy_abac=true")
    assert not _matches("gcp-gke-legacy-abac-enabled", "enable_legacy_abac = false")
    assert not _matches("gcp-gke-legacy-abac-enabled", "legacy_abac = true")


def test_gcp_service_account_key_resource():
    for r in _rules("gcp-service-account-key-resource"):
        assert r["severity"] == "WARNING"
    assert _matches(
        "gcp-service-account-key-resource",
        'resource "google_service_account_key" "ci" {\n'
        "  service_account_id = google_service_account.ci.name\n}\n",
    )
    # The service account itself (no key) must NOT match
    assert not _matches(
        "gcp-service-account-key-resource",
        'resource "google_service_account" "ci" { account_id = "ci" }',
    )
    # Data source lookups must NOT match
    assert not _matches(
        "gcp-service-account-key-resource",
        'data "google_service_account_key" "ci" {}',
    )


def test_gcp_rules_have_messages():
    for rule_id in (
        "gcp-iam-public-member",
        "gcp-firewall-open-to-world",
        "gcp-sql-public-authorized-network",
        "gcp-gke-legacy-abac-enabled",
        "gcp-service-account-key-resource",
    ):
        for r in _rules(rule_id):
            assert r["message"].strip(), f"empty message for {rule_id}"


def test_gcp_rules_end_to_end_on_terraform_file(tmp_path):
    tf = tmp_path / "main.tf"
    tf.write_text(
        'resource "google_compute_firewall" "ssh" {\n'
        '  name          = "allow-ssh"\n'
        '  source_ranges = ["0.0.0.0/0"]\n'
        "}\n"
        "\n"
        'resource "google_storage_bucket_iam_member" "pub" {\n'
        '  role   = "roles/storage.objectViewer"\n'
        '  member = "allUsers"\n'
        "}\n"
        "\n"
        'resource "google_sql_database_instance" "db" {\n'
        "  settings {\n"
        "    ip_configuration {\n"
        "      authorized_networks {\n"
        '        name  = "everyone"\n'
        '        value = "0.0.0.0/0"\n'
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
        "\n"
        'resource "google_container_cluster" "gke" {\n'
        "  enable_legacy_abac = true\n"
        "}\n"
        "\n"
        'resource "google_service_account_key" "ci" {\n'
        "  service_account_id = google_service_account.ci.name\n"
        "}\n",
        encoding="utf-8",
    )
    rule_ids = {f["rule_id"] for f in _scan_file(tf, tmp_path)}
    assert "gcp-iam-public-member" in rule_ids
    assert "gcp-firewall-open-to-world" in rule_ids
    assert "gcp-sql-public-authorized-network" in rule_ids
    assert "gcp-gke-legacy-abac-enabled" in rule_ids
    assert "gcp-service-account-key-resource" in rule_ids


def test_gcp_rules_end_to_end_clean_terraform_file(tmp_path):
    tf = tmp_path / "main.tf"
    tf.write_text(
        'resource "google_compute_firewall" "iap" {\n'
        '  name          = "allow-iap-ssh"\n'
        '  source_ranges = ["35.235.240.0/20"]\n'
        "}\n"
        "\n"
        'resource "google_storage_bucket_iam_member" "app" {\n'
        '  role   = "roles/storage.objectViewer"\n'
        '  member = "serviceAccount:app@p.iam.gserviceaccount.com"\n'
        "}\n"
        "\n"
        'resource "google_container_cluster" "gke" {\n'
        "  enable_legacy_abac = false\n"
        "}\n",
        encoding="utf-8",
    )
    gcp_findings = [
        f for f in _scan_file(tf, tmp_path) if f["rule_id"].startswith("gcp-")
    ]
    assert gcp_findings == []
