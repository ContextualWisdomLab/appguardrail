"""Source-derived regressions for bounded governance JSON and subprocess execution."""

from pathlib import Path
import tomllib

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_JSON_RULE_ID = "python-governance-unbounded-json-load"
_SUBPROCESS_RULE_ID = "python-governance-subprocess-without-timeout"
_SOURCE_REPOSITORY = "ContextualWisdomLab/fast-mlsirm"
_VULNERABLE_HEAD_SHA = "c8555c3f33a7bc8fdb2e8e0ea0f3cf2bd52ce0b9"
_VULNERABLE_BLOB_SHA = "3dab225870e5fce806047a622a605b6c451bce59"
_PARTIAL_FIXED_HEAD_SHA = "c9456a0c29c5b0c37cb11867c1a8e605738db40c"
_PARTIAL_FIXED_BLOB_SHA = "b016f8c698189d580634b81a1508f567379dcbfc"
_PROTECTED_FIXED_BLOB_SHA = "65b8b3b9e1a5c8d68987261987b9e20660e2d1ab"
_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "governance_resource_bound_sources.toml"


def _load_source_fixtures() -> dict[str, str]:
    """Load deliberately vulnerable and safe source replays as inert test data."""
    with _FIXTURE_PATH.open("rb") as fixture_file:
        fixtures = tomllib.load(fixture_file)
    assert all(isinstance(source, str) for source in fixtures.values())
    return fixtures


_SOURCE_FIXTURES = _load_source_fixtures()
_VULNERABLE_SOURCE = _SOURCE_FIXTURES["vulnerable"]
_SAFE_JSON_SOURCE = _SOURCE_FIXTURES["safe_json"]
_UNSAFE_STAT_THEN_OPEN_SOURCE = _SOURCE_FIXTURES["unsafe_stat_then_open"]
_SAFE_SUBPROCESS_SOURCE = _SOURCE_FIXTURES["safe_subprocess"]
_NON_GOVERNANCE_SOURCE = _SOURCE_FIXTURES["non_governance"]


def _rule(rule_id: str) -> dict:
    """Return one packaged resource-bound detector."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == rule_id]
    assert len(matches) == 1, f"expected one loaded rule for {rule_id}"
    return matches[0]


def _scan(source: str, tmp_path: Path) -> list[dict]:
    """Run production scanning and retain the two governance detector families."""
    source_file = tmp_path / "build_pr_queue_governance.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] in {_JSON_RULE_ID, _SUBPROCESS_RULE_ID}
    ]


def test_source_provenance_records_fast_mlsirm_revisions() -> None:
    """Pin the vulnerable, partial-fix, and protected-fix source identities."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/fast-mlsirm"
    assert _VULNERABLE_HEAD_SHA == "c8555c3f33a7bc8fdb2e8e0ea0f3cf2bd52ce0b9"
    assert _VULNERABLE_BLOB_SHA == "3dab225870e5fce806047a622a605b6c451bce59"
    assert _PARTIAL_FIXED_HEAD_SHA == "c9456a0c29c5b0c37cb11867c1a8e605738db40c"
    assert _PARTIAL_FIXED_BLOB_SHA == "b016f8c698189d580634b81a1508f567379dcbfc"
    assert _PROTECTED_FIXED_BLOB_SHA == "65b8b3b9e1a5c8d68987261987b9e20660e2d1ab"


def test_regression_corpus_is_non_executable_fixture_data() -> None:
    """Keep vulnerable replay text out of importable Python source scanned as product code."""
    assert _FIXTURE_PATH.suffix == ".toml"
    assert _FIXTURE_PATH.parent.name == "fixtures"
    assert "def _read_json" in _VULNERABLE_SOURCE
    assert "subprocess.run" in _VULNERABLE_SOURCE


def test_json_rule_detects_direct_governance_json_load() -> None:
    """Detect unbounded `json.load` in the source-derived governance reader."""
    rule = _rule(_JSON_RULE_ID)
    assert rule["severity"] == "MEDIUM"
    assert rule["pattern"].search(_VULNERABLE_SOURCE)


def test_json_rule_ignores_descriptor_safe_bounded_loader() -> None:
    """Keep the protected `read_json_object` repair negative."""
    assert not _rule(_JSON_RULE_ID)["pattern"].search(_SAFE_JSON_SOURCE)


def test_json_rule_keeps_stat_then_open_race_in_scope() -> None:
    """Do not accept path-stat then reopen as a descriptor-safe size boundary."""
    assert _rule(_JSON_RULE_ID)["pattern"].search(_UNSAFE_STAT_THEN_OPEN_SOURCE)


def test_subprocess_rule_detects_gh_commands_without_timeout() -> None:
    """Detect governance GitHub CLI subprocesses that can wait indefinitely."""
    rule = _rule(_SUBPROCESS_RULE_ID)
    assert rule["severity"] == "MEDIUM"
    assert rule["pattern"].search(_VULNERABLE_SOURCE)


def test_subprocess_rule_ignores_explicit_timeout() -> None:
    """Keep the directionally correct timeout repair negative."""
    assert not _rule(_SUBPROCESS_RULE_ID)["pattern"].search(_SAFE_SUBPROCESS_SOURCE)


def test_subprocess_rule_ignores_non_governance_command() -> None:
    """Avoid classifying arbitrary local subprocess use as PR-governance DoS."""
    assert not _rule(_SUBPROCESS_RULE_ID)["pattern"].search(_NON_GOVERNANCE_SOURCE)


def test_packaged_rules_use_parser_safe_prefilters() -> None:
    """Keep expensive source-shape expressions off unrelated Python files."""
    assert _rule(_JSON_RULE_ID)["required_substrings"] == (
        "def _read_json",
        "json.load(",
        "path.open(",
    )
    assert _rule(_SUBPROCESS_RULE_ID)["required_substrings"] == (
        "subprocess.run(",
        '"gh"',
        "def _run_gh",
    )


def test_production_scanner_emits_both_resource_bound_findings(tmp_path: Path) -> None:
    """Exercise both source-derived weaknesses through the exact scanner entrypoint."""
    findings = _scan(_VULNERABLE_SOURCE, tmp_path)
    assert {finding["rule_id"] for finding in findings} == {
        _JSON_RULE_ID,
        _SUBPROCESS_RULE_ID,
    }
    assert all(finding["severity"] == "MEDIUM" for finding in findings)
    assert all(finding["confidence"] == "high" for finding in findings)
    assert all(finding["source"] == "appguardrail-rule" for finding in findings)
    assert all(
        "CWE-400 - Uncontrolled Resource Consumption" in finding["cwe"]
        for finding in findings
    )
