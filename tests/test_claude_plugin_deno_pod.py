"""Hook deno publish and pod trunk push fail closed; info/install stay inventory."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from appguardrail_core.claude_plugin_detector import (
    _collect_plugin_hits,
    build_claude_plugin_scan_receipt,
    inspect_claude_plugin_file,
    inventory_claude_plugin_capabilities,
)


_PINNED_COMMIT = "a727be1c7bd6064419b6f60d71993a19198adc17"
_DENO_RULE = "claude-plugin-deno-publish-command"
_POD_RULE = "claude-plugin-pod-trunk-push-command"
_SBT_RULE = "claude-plugin-sbt-publish-command"
_SECRET = "sk-deno-must-not-leak"
_BIDI = "\u202e"
_THIS_CLASS = frozenset({_DENO_RULE, _POD_RULE})


def _write_json(path: Path, payload: dict) -> None:
    """Write one JSON document under ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _licensed_plugin(root: Path, hook_body: str = "#!/bin/sh\necho hello\n") -> Path:
    """Write a pinned licensed plugin with one declared shell hook."""
    _write_json(
        root / ".claude-plugin" / "plugin.json",
        {
            "name": "safe-plugin",
            "version": "1.0.0",
            "source": {
                "source": "github",
                "repo": "example/safe-plugin",
                "ref": _PINNED_COMMIT,
            },
            "hooks": {"PreToolUse": [{"command": "hooks/session.sh"}]},
        },
    )
    hook = root / "hooks" / "session.sh"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(hook_body, encoding="utf-8")
    hook.chmod(0o755)
    (root / "LICENSE").write_text("MIT\n", encoding="utf-8")
    return root


def _hits(root: Path, rule_id: str):
    """Return receipt-path hits for one rule identity."""
    return [hit for hit in _collect_plugin_hits(root) if hit.rule_id == rule_id]


def test_hook_deno_publish_fails_admission(tmp_path: Path) -> None:
    """``deno publish`` on a hook is JSR write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ndeno publish --allow-slow-types\n")
    hits = _hits(root, _DENO_RULE)
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert hits
    assert all(hit.snippet == "deno publish" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _DENO_RULE in receipt.finding_summary
    assert _POD_RULE not in receipt.finding_summary
    assert _SBT_RULE not in receipt.finding_summary
    assert inventory["package_install"] is True


def test_hook_pod_trunk_push_fails_admission(tmp_path: Path) -> None:
    """``pod trunk push`` on a hook is CocoaPods trunk write authority."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\npod trunk push App.podspec\n")
    hits = _hits(root, _POD_RULE)
    receipt = build_claude_plugin_scan_receipt(root)

    assert hits
    assert all(hit.snippet == "pod trunk push" for hit in hits)
    assert receipt.scan_result == "fail"
    assert _POD_RULE in receipt.finding_summary
    assert _DENO_RULE not in receipt.finding_summary


def test_deno_info_and_pod_install_stay_inventory(tmp_path: Path) -> None:
    """Read-only deno info and local pod install stay inventory."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\ndeno info\npod install\n")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _DENO_RULE) == []
    assert _hits(root, _POD_RULE) == []
    assert receipt.scan_result == "pass"


def test_pod_lib_lint_is_not_this_class(tmp_path: Path) -> None:
    """``pod lib lint`` stays local validation, not trunk write."""
    root = _licensed_plugin(tmp_path, "#!/bin/sh\npod lib lint\n")
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _POD_RULE) == []
    assert receipt.scan_result == "pass"


def test_sbt_and_deno_on_one_hook_are_distinct_findings(tmp_path: Path) -> None:
    """One hook can fail closed on both sbt publish and deno publish."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\nsbt publish && deno publish\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _SBT_RULE)
    assert _hits(root, _DENO_RULE)
    assert receipt.scan_result == "fail"
    assert _POD_RULE not in receipt.finding_summary


def test_sbt_publish_stays_the_sbt_class() -> None:
    """``sbt publish`` remains the sbt class, not JSR."""
    body = "#!/bin/sh\nsbt publish\n"
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    rule_ids = {hit.rule_id for hit in hits}
    assert _SBT_RULE in rule_ids
    assert _THIS_CLASS.isdisjoint(rule_ids)


def test_comment_and_echo_deno_pod_are_not_this_class(tmp_path: Path) -> None:
    """Unquoted comments and echo lookalikes are not executable publishes."""
    root = _licensed_plugin(
        tmp_path,
        '#!/bin/sh\n# deno publish\necho "pod trunk push App.podspec"\n',
    )
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _DENO_RULE) == []
    assert _hits(root, _POD_RULE) == []
    assert receipt.scan_result == "pass"


def test_assignment_values_are_not_this_class() -> None:
    """An unquoted assignment value cannot turn its following word into the CLI."""
    bodies = (
        "#!/bin/sh\nmessage=deno publish --allow-slow-types\n",
        "#!/bin/sh\ncommand=pod trunk push App.podspec\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert _THIS_CLASS.isdisjoint(hit.rule_id for hit in hits)


@pytest.mark.parametrize(
    ("body", "unexpected_rule"),
    (
        ("#!/bin/sh\npython -c pass deno publish\n", _DENO_RULE),
        ("#!/bin/sh\npython -c pass pod trunk push\n", _POD_RULE),
    ),
)
def test_argument_words_are_not_publish_commands(
    body: str, unexpected_rule: str
) -> None:
    """Arguments to another executable are not registry-write commands."""
    rule_ids = {
        hit.rule_id
        for hit in inspect_claude_plugin_file(
            "session.sh", "hooks/session.sh", body
        )
    }
    assert unexpected_rule not in rule_ids


@pytest.mark.parametrize(
    ("command", "expected_rule"),
    (
        ("exec deno publish", _DENO_RULE),
        ("exec pod trunk push App.podspec", _POD_RULE),
        ("exec gh pr merge 1", "claude-plugin-github-merge-command"),
        ("exec kubectl apply -f deploy.yaml", "claude-plugin-kubectl-apply-command"),
        ("exec npm publish", "claude-plugin-npm-publish-command"),
        ("command deno publish", _DENO_RULE),
        ("command pod trunk push App.podspec", _POD_RULE),
        ("command gh pr merge 1", "claude-plugin-github-merge-command"),
        (
            "command kubectl apply -f deploy.yaml",
            "claude-plugin-kubectl-apply-command",
        ),
        ("command npm publish", "claude-plugin-npm-publish-command"),
    ),
)
def test_bare_shell_prefix_preserves_command_execution(
    command: str, expected_rule: str
) -> None:
    """POSIX bare ``exec`` and ``command`` execute a literal utility."""
    hits = inspect_claude_plugin_file(
        "session.sh", "hooks/session.sh", f"#!/bin/sh\n{command}\n"
    )

    assert expected_rule in {hit.rule_id for hit in hits}


@pytest.mark.parametrize(
    "body",
    (
        "#!/bin/sh\necho exec deno publish\n",
        "#!/bin/sh\npython -c pass exec deno publish\n",
        "#!/bin/sh\nmessage='exec deno publish'\n",
        "#!/bin/sh\nexec deno info\n",
    ),
)
def test_exec_lookalikes_are_not_deno_publish_commands(body: str) -> None:
    """Arguments, assignment values, and read-only verbs stay outside admission."""
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)

    assert _DENO_RULE not in {hit.rule_id for hit in hits}


@pytest.mark.parametrize(
    "body",
    (
        "#!/bin/sh\necho command deno publish\n",
        "#!/bin/sh\npython -c pass command deno publish\n",
        "#!/bin/sh\nmessage='command deno publish'\n",
        "#!/bin/sh\ncommand -v deno publish\n",
        "#!/bin/sh\ncommand deno info\n",
    ),
)
def test_command_lookalikes_are_not_deno_publish_commands(body: str) -> None:
    """Reporting, arguments, assignment values, and read-only verbs stay out."""
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)

    assert _DENO_RULE not in {hit.rule_id for hit in hits}


def test_environment_assignment_before_real_command_still_fails() -> None:
    """Environment assignments do not hide a later executable registry write."""
    bodies = (
        "#!/bin/sh\nDENO_DIR=/tmp deno publish --allow-slow-types\n",
        "#!/bin/sh\nCOCOAPODS_TRUNK_TOKEN=x pod trunk push App.podspec\n",
    )
    for body in bodies:
        hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
        assert any(hit.rule_id in _THIS_CLASS for hit in hits)


def test_readme_deno_pod_is_not_this_class(tmp_path: Path) -> None:
    """README deno/pod wording is repository guidance, not a hook command."""
    root = _licensed_plugin(tmp_path)
    (root / "README.md").write_text(
        "deno publish --allow-slow-types\npod trunk push App.podspec\n",
        encoding="utf-8",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _DENO_RULE) == []
    assert _hits(root, _POD_RULE) == []
    assert receipt.scan_result == "pass"
    assert inventory["package_install"] is True


def test_echo_then_real_deno_publish_still_fails() -> None:
    """``echo done && deno publish`` still runs the registry write."""
    hits = inspect_claude_plugin_file(
        "session.sh",
        "hooks/session.sh",
        '#!/bin/sh\necho "done" && deno publish --allow-slow-types\n',
    )
    assert any(
        hit.rule_id == _DENO_RULE and hit.snippet == "deno publish" for hit in hits
    )


def test_snippets_are_command_labels_not_secrets(tmp_path: Path) -> None:
    """Snippets name the CLI command and omit secrets and bidi."""
    body = f"#!/bin/sh\ndeno publish --token {_SECRET}{_BIDI}\n"
    root = _licensed_plugin(tmp_path, body)
    hits = inspect_claude_plugin_file("session.sh", "hooks/session.sh", body)
    deno_hits = [hit for hit in hits if hit.rule_id == _DENO_RULE]
    payload = json.dumps(build_claude_plugin_scan_receipt(root).as_dict())

    assert deno_hits
    for hit in deno_hits:
        assert hit.snippet == "deno publish"
        assert _SECRET not in hit.snippet
        assert _BIDI not in hit.snippet
        assert _SECRET not in hit.message
    assert _SECRET not in payload
    assert _BIDI not in payload


def test_plugin_manifest_pod_trunk_push_fails_admission(tmp_path: Path) -> None:
    """A plugin.json command string that pushes to CocoaPods trunk is that class."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PreToolUse": [{"command": "hooks/session.sh"}],
        "PostToolUse": [{"command": "pod trunk push App.podspec"}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _POD_RULE)
    assert receipt.scan_result == "fail"


def test_structured_manifest_deno_argv_fails_admission(tmp_path: Path) -> None:
    """Direct typed Deno argv preserves the publish verb for admission."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PostToolUse": [{"command": "deno", "args": ["publish"]}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)

    receipt = build_claude_plugin_scan_receipt(root)

    assert _hits(root, _DENO_RULE)
    assert receipt.scan_result == "fail"
    assert _DENO_RULE in receipt.finding_summary


def test_structured_manifest_pod_argv_fails_admission(tmp_path: Path) -> None:
    """Direct typed CocoaPods argv preserves trunk push for admission."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PostToolUse": [{"command": "pod", "args": ["trunk", "push"]}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)

    receipt = build_claude_plugin_scan_receipt(root)

    assert _hits(root, _POD_RULE)
    assert receipt.scan_result == "fail"
    assert _POD_RULE in receipt.finding_summary


@pytest.mark.parametrize(
    ("command", "args"),
    (("deno", ["publish"]), ("pod", ["trunk", "push"])),
)
def test_structured_publish_argv_stays_package_inventory(
    tmp_path: Path, command: str, args: list[str]
) -> None:
    """Typed package-publish argv remains visible in capability inventory."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PostToolUse": [{"command": command, "args": args}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)

    inventory = inventory_claude_plugin_capabilities(root)

    assert inventory["package_install"] is True


@pytest.mark.parametrize(
    ("command", "args"),
    (
        ("deno", ["info"]),
        ("pod", ["install"]),
        ("echo", ["deno", "publish"]),
    ),
)
def test_other_structured_argv_is_not_package_publish_inventory(
    tmp_path: Path, command: str, args: list[str]
) -> None:
    """Read-only verbs and typed reporting argv are not registry writes."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PostToolUse": [{"command": command, "args": args}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)

    inventory = inventory_claude_plugin_capabilities(root)

    assert inventory["package_install"] is False


@pytest.mark.parametrize("wrapper", ("exec", "command"))
def test_structured_shell_wrapper_argv_has_no_builtin_semantics(
    tmp_path: Path, wrapper: str
) -> None:
    """Typed process argv does not imply POSIX shell-builtin semantics."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PostToolUse": [{"command": wrapper, "args": ["deno", "publish"]}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)

    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _DENO_RULE) == []
    assert _DENO_RULE not in receipt.finding_summary
    assert inventory["package_install"] is False


@pytest.mark.parametrize(
    ("command", "args", "expected_rule"),
    (
        ("env", ["deno", "publish"], _DENO_RULE),
        ("env", ["DENO_DIR=/tmp", "deno", "publish"], _DENO_RULE),
        (
            "/usr/bin/env",
            [
                "--ignore-environment",
                "COCOAPODS_TRUNK_TOKEN=x",
                "pod",
                "trunk",
                "push",
            ],
            _POD_RULE,
        ),
        ("env", ["--", "deno", "publish"], _DENO_RULE),
    ),
)
def test_structured_env_wrapped_publish_fails_admission(
    tmp_path: Path, command: str, args: list[str], expected_rule: str
) -> None:
    """A bounded typed ``env`` wrapper preserves registry-write authority."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PostToolUse": [{"command": command, "args": args}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)

    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, expected_rule)
    assert receipt.scan_result == "fail"
    assert inventory["package_install"] is True


@pytest.mark.parametrize(
    "args",
    (
        ["DENO_DIR=/tmp"],
        ["echo", "deno", "publish"],
        ["DENO_DIR=/tmp", "--", "deno", "publish"],
        ["--", "DENO_DIR=/tmp", "--", "pod", "trunk", "push"],
    ),
)
def test_structured_env_without_direct_publish_stays_outside_class(
    tmp_path: Path, args: list[str]
) -> None:
    """Incomplete, reporting, and post-assignment ``--`` stay outside."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PostToolUse": [{"command": "env", "args": args}],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)

    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
    assert inventory["package_install"] is False


def test_nested_shell_manifest_deno_publish_fails_admission(tmp_path: Path) -> None:
    """A typed Bash payload preserves executable Deno registry authority."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PostToolUse": [
            {"command": "bash", "args": ["-c", "deno publish"]},
        ],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)

    receipt = build_claude_plugin_scan_receipt(root)

    assert _hits(root, _DENO_RULE)
    assert receipt.scan_result == "fail"


def test_nested_shell_manifest_pod_push_fails_admission(tmp_path: Path) -> None:
    """A typed POSIX shell payload preserves executable CocoaPods authority."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["hooks"] = {
        "PostToolUse": [
            {"command": "sh", "args": ["-c", "pod trunk push App.podspec"]},
        ],
    }
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)

    receipt = build_claude_plugin_scan_receipt(root)

    assert _hits(root, _POD_RULE)
    assert receipt.scan_result == "fail"


@pytest.mark.parametrize(
    ("shell", "payload", "escaped_payload"),
    (
        ("bash", "deno publish", r"deno\u0020publish"),
        (
            "sh",
            "pod trunk push App.podspec",
            r"pod\u0020trunk\u0020push App.podspec",
        ),
    ),
)
def test_json_escaped_nested_publish_stays_package_inventory(
    tmp_path: Path, shell: str, payload: str, escaped_payload: str
) -> None:
    """Decoded shell publish payloads remain visible in capability inventory."""
    root = _licensed_plugin(tmp_path)
    manifest_path = root / ".claude-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["hooks"] = {
        "PostToolUse": [{"command": shell, "args": ["-c", payload]}],
    }
    source = json.dumps(manifest, indent=2).replace(payload, escaped_payload) + "\n"
    manifest_path.write_text(source, encoding="utf-8")

    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert receipt.scan_result == "fail"
    assert inventory["package_install"] is True


def test_json_escaped_nested_reporting_stays_outside_package_inventory(
    tmp_path: Path,
) -> None:
    """Decoded reporting payload text is not executable registry authority."""
    root = _licensed_plugin(tmp_path)
    manifest_path = root / ".claude-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload = "echo deno publish"
    manifest["hooks"] = {
        "PostToolUse": [{"command": "bash", "args": ["-c", payload]}],
    }
    source = json.dumps(manifest, indent=2).replace(
        payload, r"echo\u0020deno\u0020publish"
    ) + "\n"
    manifest_path.write_text(source, encoding="utf-8")

    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _DENO_RULE) == []
    assert _hits(root, _POD_RULE) == []
    assert inventory["package_install"] is False


def test_nested_shell_kubectl_then_deno_reports_both_commands(
    tmp_path: Path,
) -> None:
    """A preceding kubectl write cannot consume the later Deno finding."""
    root = _licensed_plugin(tmp_path)
    manifest_path = root / ".claude-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["hooks"] = {
        "PostToolUse": [
            {
                "command": "bash",
                "args": ["-c", "kubectl apply -f deploy.yaml && deno publish"],
            }
        ],
    }
    _write_json(manifest_path, manifest)

    rule_ids = {hit.rule_id for hit in _collect_plugin_hits(root)}

    assert "claude-plugin-kubectl-apply-command" in rule_ids
    assert _DENO_RULE in rule_ids


def test_manifest_prose_is_not_this_class(tmp_path: Path) -> None:
    """Marketplace description prose about deno publish is not a command."""
    root = _licensed_plugin(tmp_path)
    manifest = json.loads(
        (root / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    manifest["description"] = "Never runs deno publish or pod trunk push."
    _write_json(root / ".claude-plugin" / "plugin.json", manifest)
    receipt = build_claude_plugin_scan_receipt(root)
    assert _hits(root, _DENO_RULE) == []
    assert _hits(root, _POD_RULE) == []
    assert receipt.scan_result == "pass"



def test_quoted_deno_publish_task_fails_admission(tmp_path: Path) -> None:
    """A quoted exact Deno task remains executable JSR write authority."""
    root = _licensed_plugin(
        tmp_path,
        '#!/bin/sh\ndeno "publish" --allow-slow-types\n',
    )
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _DENO_RULE)
    assert receipt.scan_result == "fail"
    assert inventory["package_install"] is True


def test_quoted_pod_push_task_fails_admission(tmp_path: Path) -> None:
    """A quoted exact CocoaPods verb remains executable trunk write authority."""
    root = _licensed_plugin(
        tmp_path,
        "#!/bin/sh\npod trunk 'push' App.podspec\n",
    )
    receipt = build_claude_plugin_scan_receipt(root)
    inventory = inventory_claude_plugin_capabilities(root)

    assert _hits(root, _POD_RULE)
    assert receipt.scan_result == "fail"
    assert inventory["package_install"] is True



def test_quoted_cli_names_still_fail_admission(tmp_path: Path) -> None:
    """Quoting an exact CLI name does not remove its registry write authority."""
    cases = (
        ("deno", '#!/bin/sh\n"deno" publish --allow-slow-types\n', _DENO_RULE),
        ("pod", "#!/bin/sh\n'pod' trunk push App.podspec\n", _POD_RULE),
    )
    for name, body, expected_rule in cases:
        root = _licensed_plugin(tmp_path / name, body)
        assert _hits(root, expected_rule)
        assert build_claude_plugin_scan_receipt(root).scan_result == "fail"
        assert inventory_claude_plugin_capabilities(root)["package_install"] is True



def test_quoted_task_suffixes_are_not_publish_capabilities(tmp_path: Path) -> None:
    """Quoted near-task names stay outside admission and capability inventory."""
    cases = (
        ("deno-near", '#!/bin/sh\ndeno "publish"Local\n'),
        ("pod-near", "#!/bin/sh\npod trunk 'push'Local\n"),
    )
    for name, body in cases:
        root = _licensed_plugin(tmp_path / name, body)
        receipt = build_claude_plugin_scan_receipt(root)
        assert _THIS_CLASS.isdisjoint(receipt.finding_summary)
        assert inventory_claude_plugin_capabilities(root)["package_install"] is False
