"""Tests for the AWS CloudFormation misconfiguration rule pack."""

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_CFN_RULE_IDS = {
    "cfn-s3-bucket-public-acl",
    "cfn-security-group-open-world",
    "cfn-iam-policy-star-star",
    "cfn-rds-publicly-accessible",
    "cfn-storage-unencrypted",
    "cfn-secret-parameter-default",
}

_BY_ID = {}
for _rule in SCAN_RULES:
    if _rule["id"] in _CFN_RULE_IDS:
        _BY_ID.setdefault(_rule["id"], []).append(_rule)


def _rules(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


def _matches(rule_id, text):
    return any(rule["pattern"].search(text) for rule in _rules(rule_id))


def _severity(rule_id):
    severities = {rule["severity"] for rule in _rules(rule_id)}
    assert len(severities) == 1
    return severities.pop()


# ---------------------------------------------------------------------------
# Fixtures. Secret-shaped values are assembled at runtime so the repository
# self-scan never sees a literal misconfigured template in this file.
# ---------------------------------------------------------------------------


def _cfn_lines(*lines):
    return "\n".join(lines) + "\n"


def _s3_bucket(access_control):
    return _cfn_lines(
        "Resources:",
        "  AssetsBucket:",
        "    Type: AWS::S3::Bucket",
        "    Properties:",
        "      BucketName: app-assets",
        "      " + "AccessControl: " + access_control,
    )


def _security_group(cidr, egress_cidr="10.0.0.0/8"):
    return _cfn_lines(
        "Resources:",
        "  WebSecurityGroup:",
        "    Type: AWS::EC2::SecurityGroup",
        "    Properties:",
        "      GroupDescription: web tier",
        "      SecurityGroupIngress:",
        "        - IpProtocol: tcp",
        "          FromPort: 22",
        "          ToPort: 22",
        "          " + "CidrIp: " + cidr,
        "      SecurityGroupEgress:",
        "        - IpProtocol: -1",
        "          " + "CidrIp: " + egress_cidr,
    )


def _iam_policy(action, resource):
    return _cfn_lines(
        "      Policies:",
        "        - PolicyName: app-policy",
        "          PolicyDocument:",
        "            Version: '2012-10-17'",
        "            Statement:",
        "              - Effect: Allow",
        "                " + "Action: " + action,
        "                " + "Resource: " + resource,
    )


def _rds_instance(publicly_accessible, storage_encrypted):
    return _cfn_lines(
        "Resources:",
        "  AppDatabase:",
        "    Type: AWS::RDS::DBInstance",
        "    Properties:",
        "      Engine: postgres",
        "      " + "PubliclyAccessible: " + publicly_accessible,
        "      " + "StorageEncrypted: " + storage_encrypted,
    )


def _secret_parameter(name, extra_lines=()):
    return _cfn_lines(
        "Parameters:",
        "  " + name + ":",
        "    Type: String",
        *("    " + line for line in extra_lines),
    )


# ---------------------------------------------------------------------------
# cfn-s3-bucket-public-acl
# ---------------------------------------------------------------------------


def test_s3_public_acl_positive_yaml():
    assert _matches("cfn-s3-bucket-public-acl", _s3_bucket("PublicRead"))
    assert _matches("cfn-s3-bucket-public-acl", _s3_bucket("PublicReadWrite"))


def test_s3_public_acl_positive_json():
    template = (
        '{"Resources": {"Assets": {"Type": "AWS::S3::Bucket", '
        '"Properties": {"AccessControl": "PublicRead"}}}}'
    )
    assert _matches("cfn-s3-bucket-public-acl", template)


def test_s3_public_acl_negative():
    assert not _matches("cfn-s3-bucket-public-acl", _s3_bucket("Private"))
    assert not _matches("cfn-s3-bucket-public-acl", _s3_bucket("AuthenticatedRead"))


def test_s3_public_acl_severity():
    assert _severity("cfn-s3-bucket-public-acl") == "HIGH"


# ---------------------------------------------------------------------------
# cfn-security-group-open-world
# ---------------------------------------------------------------------------


def test_security_group_open_world_positive():
    assert _matches("cfn-security-group-open-world", _security_group("0.0.0.0/0"))
    standalone = _cfn_lines(
        "  SshIngress:",
        "    Type: AWS::EC2::SecurityGroupIngress",
        "    Properties:",
        "      IpProtocol: tcp",
        "      " + "CidrIpv6: ::/0",
    )
    assert _matches("cfn-security-group-open-world", standalone)


def test_security_group_open_world_negative_scoped_cidr():
    assert not _matches("cfn-security-group-open-world", _security_group("10.0.0.0/8"))
    assert not _matches(
        "cfn-security-group-open-world", _security_group("192.168.1.0/24")
    )


def test_security_group_open_world_negative_egress_only():
    # Open egress is the AWS default and must not trip the ingress rule.
    open_egress = _security_group("10.0.0.0/8", egress_cidr="0.0.0.0/0")
    assert not _matches("cfn-security-group-open-world", open_egress)


def test_security_group_open_world_severity():
    assert _severity("cfn-security-group-open-world") == "HIGH"


# ---------------------------------------------------------------------------
# cfn-iam-policy-star-star
# ---------------------------------------------------------------------------


def test_iam_star_star_positive():
    assert _matches("cfn-iam-policy-star-star", _iam_policy("'*'", "'*'"))
    json_statement = '{"Effect": "Allow", "Action": "*", "Resource": "*"}'
    assert _matches("cfn-iam-policy-star-star", json_statement)
    list_form = _cfn_lines(
        "            Statement:",
        "              - Effect: Allow",
        "                Action:",
        "                  - '*'",
        "                Resource:",
        "                  - '*'",
    )
    assert _matches("cfn-iam-policy-star-star", list_form)


def test_iam_star_star_negative_scoped():
    assert not _matches(
        "cfn-iam-policy-star-star", _iam_policy("'s3:GetObject'", "'*'")
    )
    assert not _matches(
        "cfn-iam-policy-star-star",
        _iam_policy("'*'", "!GetAtt AssetsBucket.Arn"),
    )


def test_iam_star_star_negative_across_statements():
    # Wildcards split across two statements are not a *:* grant.
    two_statements = _iam_policy("'*'", "arn:aws:s3:::assets/*") + _cfn_lines(
        "              - Effect: Allow",
        "                Action: s3:GetObject",
        "                Resource: '*'",
    )
    assert not _matches("cfn-iam-policy-star-star", two_statements)


def test_iam_star_star_severity():
    assert _severity("cfn-iam-policy-star-star") == "CRITICAL"


# ---------------------------------------------------------------------------
# cfn-rds-publicly-accessible
# ---------------------------------------------------------------------------


def test_rds_publicly_accessible_positive():
    assert _matches("cfn-rds-publicly-accessible", _rds_instance("true", "true"))
    assert _matches("cfn-rds-publicly-accessible", '"PubliclyAccessible": true')


def test_rds_publicly_accessible_negative():
    assert not _matches("cfn-rds-publicly-accessible", _rds_instance("false", "true"))
    # CDK TypeScript casing must not match the CFN-cased rule.
    assert not _matches("cfn-rds-publicly-accessible", "publiclyAccessible: true,")


def test_rds_publicly_accessible_severity():
    assert _severity("cfn-rds-publicly-accessible") == "HIGH"


# ---------------------------------------------------------------------------
# cfn-storage-unencrypted
# ---------------------------------------------------------------------------


def test_storage_unencrypted_positive():
    assert _matches("cfn-storage-unencrypted", _rds_instance("false", "false"))
    volume = _cfn_lines(
        "  DataVolume:",
        "    Type: AWS::EC2::Volume",
        "    Properties:",
        "      Size: 100",
        "      " + "Encrypted: false",
    )
    assert _matches("cfn-storage-unencrypted", volume)


def test_storage_unencrypted_negative():
    assert not _matches("cfn-storage-unencrypted", _rds_instance("false", "true"))
    # A bare Encrypted flag without an EBS volume context must not match.
    assert not _matches("cfn-storage-unencrypted", "encrypted: false")


def test_storage_unencrypted_severity():
    assert _severity("cfn-storage-unencrypted") == "HIGH"


# ---------------------------------------------------------------------------
# cfn-secret-parameter-default
# ---------------------------------------------------------------------------


def test_secret_parameter_default_positive():
    fixture = _secret_parameter(
        "DatabasePassword",
        ("NoEcho: true", "Default: " + "Sup3r" + "Secret!"),
    )
    assert _matches("cfn-secret-parameter-default", fixture)
    json_fixture = '"ApiToken": {"Type": "String", "Default": "' + "tok-1234" + '"}'
    assert _matches("cfn-secret-parameter-default", json_fixture)


def test_secret_parameter_default_negative_no_default():
    fixture = _secret_parameter("DatabasePassword", ("NoEcho: true",))
    assert not _matches("cfn-secret-parameter-default", fixture)


def test_secret_parameter_default_negative_next_parameter():
    # A harmless default on the FOLLOWING parameter must not be attributed
    # to the secret-named parameter above it.
    fixture = _secret_parameter("DatabasePassword", ("NoEcho: true",))
    fixture += _cfn_lines("  DbUser:", "    Type: String", "    Default: admin")
    assert not _matches("cfn-secret-parameter-default", fixture)


def test_secret_parameter_default_negative_dynamic_reference():
    fixture = _secret_parameter(
        "ApiToken",
        ("Default: '{{resolve:secretsmanager:prod/api:SecretString:token}}'",),
    )
    assert not _matches("cfn-secret-parameter-default", fixture)


def test_secret_parameter_default_severity():
    assert _severity("cfn-secret-parameter-default") == "HIGH"


# ---------------------------------------------------------------------------
# End-to-end scans
# ---------------------------------------------------------------------------


def _cfn_finding_ids(path, base):
    return {
        finding["rule_id"]
        for finding in _scan_file(path, base)
        if finding["rule_id"].startswith("cfn-")
    }


def test_e2e_misconfigured_template_fires_all_rules(tmp_path):
    template = (
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        + _secret_parameter("DatabasePassword", ("Default: " + "Sup3r" + "Secret!",))
        + _s3_bucket("PublicRead")
        + _security_group("0.0.0.0/0")
        + _iam_policy("'*'", "'*'")
        + _rds_instance("true", "false")
    )
    template_file = tmp_path / "template.yaml"
    template_file.write_text(template, encoding="utf-8")
    assert _cfn_finding_ids(template_file, tmp_path) == _CFN_RULE_IDS


def test_e2e_secure_template_is_clean(tmp_path):
    template = (
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        + _secret_parameter("DatabasePassword", ("NoEcho: true",))
        + _s3_bucket("Private")
        + _security_group("10.0.0.0/8")
        + _iam_policy("'s3:GetObject'", "!GetAtt AssetsBucket.Arn")
        + _rds_instance("false", "true")
    )
    template_file = tmp_path / "template.yaml"
    template_file.write_text(template, encoding="utf-8")
    assert _cfn_finding_ids(template_file, tmp_path) == set()


def test_e2e_kubernetes_manifest_is_clean(tmp_path):
    manifest = _cfn_lines(
        "apiVersion: apps/v1",
        "kind: Deployment",
        "metadata:",
        "  name: web",
        "spec:",
        "  template:",
        "    spec:",
        "      serviceAccountToken:",
        "        expirationSeconds: 3600",
        "      containers:",
        "        - name: web",
        "          image: nginx:1.27",
        "          resources:",
        "            limits:",
        "              cpu: '1'",
        "          ports:",
        "            - containerPort: 8080",
        "              hostIP: 0.0.0.0",
    )
    manifest_file = tmp_path / "deployment.yaml"
    manifest_file.write_text(manifest, encoding="utf-8")
    assert _cfn_finding_ids(manifest_file, tmp_path) == set()


def test_e2e_docker_compose_is_clean(tmp_path):
    compose = _cfn_lines(
        "services:",
        "  db:",
        "    image: postgres:16",
        "    ports:",
        "      - '0.0.0.0:5432:5432'",
        "    environment:",
        "      POSTGRES_HOST_AUTH_METHOD: trust",
        "    volumes:",
        "      - db-data:/var/lib/postgresql/data",
        "volumes:",
        "  db-data:",
    )
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(compose, encoding="utf-8")
    assert _cfn_finding_ids(compose_file, tmp_path) == set()


def test_e2e_github_workflow_is_clean(tmp_path):
    workflow = _cfn_lines(
        "name: ci",
        "on:",
        "  workflow_call:",
        "    inputs:",
        "      token:",
        "        description: registry token",
        "        required: false",
        "        default: placeholder-token",
        "        type: string",
        "jobs:",
        "  build:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "      - run: make test",
    )
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    workflow_file = workflow_dir / "ci.yml"
    workflow_file.write_text(workflow, encoding="utf-8")
    assert _cfn_finding_ids(workflow_file, tmp_path) == set()


def test_e2e_rules_do_not_apply_to_python_sources(tmp_path):
    source = 'CONFIG = {"PubliclyAccessible": True}\n'
    source_file = tmp_path / "deploy_config.py"
    source_file.write_text(source, encoding="utf-8")
    assert _cfn_finding_ids(source_file, tmp_path) == set()
