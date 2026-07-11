"""Precision tests for the Ansible playbook rule pack (scanner/rules/ansible.yml)."""

import pytest

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_BY_ID = {}
for _r in SCAN_RULES:
    _BY_ID.setdefault(_r["id"], _r)

ANSIBLE_RULE_IDS = [
    "ansible-shell-command-injection",
    "ansible-validate-certs-false",
    "ansible-become-password-literal",
    "ansible-ssh-password-literal",
    "ansible-file-mode-world-writable",
    "ansible-host-key-checking-disabled",
]

# Secret-shaped fixture values are assembled at runtime so the repository
# self-scan never sees a literal credential in this file.
_FAKE_PASS = "hunter" + "2" + "secret"
_FAKE_ROOT_PASS = "S3cr3t" + "9" + "Root"


def _rule(rule_id):
    assert rule_id in _BY_ID, f"rule not loaded: {rule_id}"
    return _BY_ID[rule_id]


CASES = {
    "ansible-shell-command-injection": (
        [
            "- shell: rm -rf /tmp/{{ user_dir }}",
            "  command: /usr/bin/deploy {{ app_version }}",
            "- ansible.builtin.shell: echo {{ payload }} > /etc/motd",
            '  command: "{{ deploy_cmd }}"',
        ],
        [
            "shell: bash",  # GitHub Actions step option
            '      run: echo "${{ secrets.TOKEN }}"',  # GitHub Actions expression
            '  command: ["/bin/sh", "-c", "echo hi"]',  # Kubernetes container
            '  command: ["{{ .Values.cmd }}"]',  # Helm template list
            "  command: {{ .Values.command }}",  # Helm template scalar
            '  command: {{ include "app.cmd" . }}',  # Helm include helper
            "- shell: systemctl restart nginx",  # Ansible without interpolation
            "  command: npm run start",  # docker-compose service
        ],
    ),
    "ansible-validate-certs-false": (
        [
            "    validate_certs: false",
            "validate_certs: no",
            '  validate_certs: "false"',
        ],
        [
            "validate_certs: true",
            "# validate_certs: false",
            "insecure_skip_tls_verify: true",  # kubeconfig look-alike
            "validate_certs: nothing",
        ],
    ),
    "ansible-become-password-literal": (
        [
            f"ansible_become_pass: {_FAKE_PASS}",
            f'  ansible_become_password: "{_FAKE_ROOT_PASS}"',
        ],
        [
            'ansible_become_pass: "{{ vault_become_pass }}"',
            "ansible_become_pass: {{ vault_become_pass }}",
            "ansible_become_pass: !vault |",
            "ansible_become_method: sudo",
        ],
    ),
    "ansible-ssh-password-literal": (
        [
            f"ansible_ssh_pass: {_FAKE_PASS}",
            f'    ansible_password: "{_FAKE_ROOT_PASS}"',
        ],
        [
            'ansible_ssh_pass: "{{ vault_ssh_pass }}"',
            "ansible_password: !vault |",
            "ansible_ssh_private_key_file: ~/.ssh/id_ed25519",
        ],
    ),
    "ansible-file-mode-world-writable": (
        [
            "    mode: '0777'",
            "mode: 0777",
            '  mode: "777"',
            "  mode: 0666",
        ],
        [
            "mode: '0644'",
            "      defaultMode: 0777",  # Kubernetes configMap key
            "mode: 0444",
            "network_mode: host",  # docker-compose
            "mode: 06660",
        ],
    ),
    "ansible-host-key-checking-disabled": (
        [
            "host_key_checking = False",  # ansible.cfg
            "ansible_host_key_checking: false",
            "ansible_ssh_host_key_checking: no",
        ],
        [
            "host_key_checking = True",
            "# host_key_checking = False",
            "StrictHostKeyChecking no",  # ssh_config, different syntax
        ],
    ),
}


@pytest.mark.parametrize("rule_id", CASES.keys())
def test_rule_precision(rule_id):
    rule = _rule(rule_id)
    positives, negatives = CASES[rule_id]
    assert len(positives) >= 2 and len(negatives) >= 2
    for s in positives:
        assert rule["pattern"].search(s), f"{rule_id} should match: {s!r}"
    for s in negatives:
        assert not rule["pattern"].search(s), f"{rule_id} false-positive on: {s!r}"


def test_all_rules_loaded_with_yaml_scope():
    for rule_id in ANSIBLE_RULE_IDS:
        rule = _rule(rule_id)
        assert "**/*.yml" in rule["include_paths"], rule_id
        assert "**/*.yaml" in rule["include_paths"], rule_id


def test_severities():
    assert _rule("ansible-become-password-literal")["severity"] == "CRITICAL"
    assert _rule("ansible-ssh-password-literal")["severity"] == "CRITICAL"
    assert _rule("ansible-shell-command-injection")["severity"] == "HIGH"
    assert _rule("ansible-validate-certs-false")["severity"] == "HIGH"
    assert _rule("ansible-file-mode-world-writable")["severity"] == "HIGH"
    assert _rule("ansible-host-key-checking-disabled")["severity"] == "HIGH"


def test_e2e_vulnerable_playbook(tmp_path):
    playbook = tmp_path / "site.yml"
    playbook.write_text(
        "\n".join(
            [
                "- hosts: all",
                "  vars:",
                f"    ansible_become_pass: {_FAKE_PASS}",
                f"    ansible_ssh_pass: {_FAKE_PASS}",
                "  tasks:",
                "    - name: fetch installer",
                "      get_url:",
                "        url: https://internal.example/pkg.rpm",
                "        dest: /tmp/pkg.rpm",
                "        validate_certs: false",
                "    - name: run user command",
                "      shell: /opt/deploy {{ user_input }}",
                "    - name: drop config",
                "      copy:",
                "        dest: /etc/app.conf",
                "        content: hi",
                "        mode: '0777'",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    inventory_cfg = tmp_path / "ansible.cfg"
    inventory_cfg.write_text(
        "[defaults]\nhost_key_checking = False\n", encoding="utf-8"
    )

    found = {f["rule_id"] for f in _scan_file(playbook, tmp_path)}
    for rule_id in ANSIBLE_RULE_IDS[:5]:
        assert rule_id in found, f"e2e miss: {rule_id}"

    cfg_found = {f["rule_id"] for f in _scan_file(inventory_cfg, tmp_path)}
    assert "ansible-host-key-checking-disabled" in cfg_found


def test_e2e_lookalike_yaml_stays_clean(tmp_path):
    k8s = tmp_path / "deployment.yaml"
    k8s.write_text(
        "\n".join(
            [
                "apiVersion: apps/v1",
                "kind: Deployment",
                "spec:",
                "  template:",
                "    spec:",
                "      containers:",
                "        - name: app",
                '          command: ["/bin/sh", "-c", "echo hi"]',
                "      volumes:",
                "        - name: cfg",
                "          configMap:",
                "            defaultMode: 0644",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "\n".join(
            [
                "services:",
                "  web:",
                "    image: nginx",
                "    command: npm run start",
                "    network_mode: host",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    workflow = tmp_path / "ci.yml"
    workflow.write_text(
        "\n".join(
            [
                "jobs:",
                "  build:",
                "    steps:",
                "      - run: echo hello",
                "        shell: bash",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    helm = tmp_path / "helm-deploy.yaml"
    helm.write_text(
        "\n".join(
            [
                "spec:",
                "  containers:",
                "    - name: app",
                '      command: ["{{ .Values.cmd }}"]',
                "      args: {{ .Values.args }}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    for path in (k8s, compose, workflow, helm):
        hits = [
            f["rule_id"]
            for f in _scan_file(path, tmp_path)
            if f["rule_id"] in ANSIBLE_RULE_IDS
        ]
        assert hits == [], f"look-alike false positive in {path.name}: {hits}"


def test_e2e_non_yaml_file_is_out_of_scope(tmp_path):
    script = tmp_path / "notes.py"
    script.write_text(
        'EXAMPLE = "validate_certs: false"\n', encoding="utf-8"
    )
    hits = [
        f["rule_id"]
        for f in _scan_file(script, tmp_path)
        if f["rule_id"] in ANSIBLE_RULE_IDS
    ]
    assert hits == []
