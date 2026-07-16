"""Tests for CycloneDX SBOM generation (appguardrail_core.sbom)."""

import json

import pytest

from appguardrail_core.sbom import (
    ManifestParseError,
    build_sbom,
    collect_components,
    parse_package_json,
    parse_package_lock,
    parse_requirements,
)


def test_package_json_strips_ranges(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"next":"^14.1.0"},"devDependencies":{"jest":"29.0.0"}}'
    )
    comps = {c["name"]: c for c in parse_package_json(tmp_path / "package.json")}
    assert comps["next"]["version"] == "14.1.0"
    assert comps["next"]["purl"] == "pkg:npm/next@14.1.0"
    assert comps["next"]["properties"][0]["value"] == "declared"


def test_package_lock_uses_resolved(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"packages": {"": {}, "node_modules/next": {"version": "14.1.2"}}})
    )
    comps = {c["name"]: c for c in parse_package_lock(tmp_path / "package-lock.json")}
    assert comps["next"]["version"] == "14.1.2"
    assert comps["next"]["properties"][0]["value"] == "resolved"


def test_package_lock_preserves_duplicate_installed_versions(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {},
                    "node_modules/minimist": {"version": "0.0.8"},
                    "node_modules/foo/node_modules/minimist": {"version": "1.2.8"},
                }
            }
        )
    )
    comps = parse_package_lock(tmp_path / "package-lock.json")
    assert {(c["name"], c["version"]) for c in comps} == {
        ("minimist", "0.0.8"),
        ("minimist", "1.2.8"),
    }


@pytest.mark.parametrize("name", ["package.json", "package-lock.json"])
def test_json_manifest_rejects_excessive_nesting_without_recursion(name, tmp_path):
    manifest = tmp_path / name
    manifest.write_text("[" * 10_000 + "]" * 10_000)
    parser = parse_package_json if name == "package.json" else parse_package_lock
    with pytest.raises(ManifestParseError, match="maximum JSON nesting depth"):
        parser(manifest)


def test_requirements_pins_only(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "flask==3.0.0\nrequests>=2.28\n# comment\n-e .\nhttps://x/y.whl\n"
    )
    comps = {c["name"]: c for c in parse_requirements(tmp_path / "requirements.txt")}
    assert comps["flask"]["version"] == "3.0.0"
    assert "version" not in comps["requests"]  # unpinned
    assert comps["requests"]["purl"] == "pkg:pypi/requests"
    assert set(comps) == {"flask", "requests"}  # -e and url lines skipped


def test_collect_prefers_lockfile(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"next":"^14.0.0"}}')
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/next": {"version": "14.1.9"}}})
    )
    comps = {c["name"]: c for c in collect_components(tmp_path)}
    assert comps["next"]["version"] == "14.1.9"  # lockfile wins


def test_build_sbom_shape(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")
    sbom = build_sbom(collect_components(tmp_path), "demo")
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["metadata"]["component"]["name"] == "demo"
    assert len(sbom["components"]) == 1


def test_dedupes(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\nflask==3.0.0\n")
    assert len(collect_components(tmp_path)) == 1
