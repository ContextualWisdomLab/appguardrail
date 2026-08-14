"""Regression tests for URL-path canonicalization-order detector variants."""

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "python-url-path-traversal-validate-before-canonicalize"


def _rules():
    """Return all packaged source-shape variants for the weakness identity."""
    matches = tuple(rule for rule in SCAN_RULES if rule["id"] == _RULE_ID)
    assert len(matches) == 2, f"expected two loaded variants for {_RULE_ID}"
    return matches


def _raw_path_validation_source():
    """Build a related source shape that validates an encoded path directly."""
    return "\n".join(
        [
            "def _txt_context_path(records: list[str]) -> str | None:",
            "    for record in records:",
            "        for raw_item in record.split():",
            '            key, separator, value = raw_item.partition("=")',
            "            if not separator:",
            "                continue",
            '            if key.strip().lower() != "path":',
            "                continue",
            "            path = value.strip()",
            "            if (",
            '                path.startswith("/")',
            '                and "://" not in path',
            '                and "\\\\" not in path',
            '                and "?" not in path',
            '                and "#" not in path',
            "                and all(",
            '                    segment not in {".", ".."}',
            '                    for segment in path.split("/")',
            "                )",
            "            ):",
            "                return path",
            "    return None",
            "",
        ]
    )


def _canonicalized_source():
    """Build a bounded canonicalize-then-validate implementation."""
    return "\n".join(
        [
            "from unicodedata import category",
            "from urllib.parse import unquote",
            "",
            "_MAX_DECODE_ROUNDS = 5",
            "",
            "def _txt_context_path(records: list[str]) -> str | None:",
            "    for record in records:",
            "        for raw_item in record.split():",
            '            key, separator, value = raw_item.partition("=")',
            "            if not separator:",
            "                continue",
            '            if key.strip().lower() != "path":',
            "                continue",
            "            path = value.strip()",
            "            decoded_path = path",
            "            for _ in range(_MAX_DECODE_ROUNDS):",
            "                next_path = unquote(decoded_path)",
            "                if next_path == decoded_path:",
            "                    break",
            "                decoded_path = next_path",
            "            else:",
            "                if unquote(decoded_path) != decoded_path:",
            "                    continue",
            "            if (",
            '                decoded_path.startswith("/")',
            '                and "://" not in decoded_path',
            '                and "\\\\" not in decoded_path',
            '                and "?" not in decoded_path',
            '                and "#" not in decoded_path',
            "                and all(",
            '                    segment not in {".", ".."}',
            '                    for segment in decoded_path.split("/")',
            "                )",
            '                and all(category(ch) != "Cc" for ch in decoded_path)',
            "            ):",
            "                return decoded_path",
            "    return None",
            "",
        ]
    )


def _recanonicalized_raw_return_source():
    """Build a safe flow where the original name is canonicalized before return."""
    return "\n".join(
        [
            "from urllib.parse import unquote",
            "",
            "def normalize_path(value):",
            "    path = value.strip()",
            "    decoded_path = path",
            "    decoded_path = unquote(decoded_path)",
            "    if (",
            '        decoded_path.startswith("/")',
            '        and "://" not in decoded_path',
            "        and all(",
            '            segment not in {".", ".."}',
            '            for segment in decoded_path.split("/")',
            "        )",
            "    ):",
            "        path = unquote(path)",
            "        return path",
            "    return None",
            "",
        ]
    )


def _single_decode_source():
    """Build a same-variable decode that occurs before URI-path validation."""
    return "\n".join(
        [
            "from urllib.parse import unquote",
            "",
            "def normalize_path(value):",
            "    path = value.strip()",
            "    path = unquote(path)",
            "    if (",
            '        path.startswith("/")',
            '        and "://" not in path',
            '        and "?" not in path',
            '        and "#" not in path',
            "        and all(",
            '            segment not in {".", ".."} for segment in path.split("/")',
            "        )",
            "    ):",
            "        return path",
            "    return None",
            "",
        ]
    )


def _non_uri_local_path_source():
    """Build a literal filesystem segment check outside a URL-path contract."""
    return "\n".join(
        [
            "def normalize_local_path(value):",
            "    path = value.strip()",
            "    if (",
            '        path.startswith("/")',
            "        and all(",
            '            segment not in {".", ".."} for segment in path.split("/")',
            "        )",
            "    ):",
            "        return path",
            "    return None",
            "",
        ]
    )


def _scan_rule_findings(tmp_path, source):
    """Run the production scanner and return only canonicalization findings."""
    source_file = tmp_path / "carddav_discovery.py"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_packaged_rules_detect_raw_path_validation_bypass():
    """Detect literal dot-segment validation that returns the encoded path."""
    rules = _rules()
    assert all(rule["severity"] == "HIGH" for rule in rules)
    assert sum(
        bool(rule["pattern"].search(_raw_path_validation_source()))
        for rule in rules
    ) == 1


def test_packaged_rules_declare_bounded_prefilter():
    """Avoid evaluating either multiline regex for unrelated Python files."""
    expected = (".split(", ".startswith(", "://", "return")
    assert all(rule["required_substrings"] == expected for rule in _rules())


def test_packaged_rules_ignore_canonicalize_then_validate_flow():
    """Do not flag a canonical representation used for validation and return."""
    assert all(
        not rule["pattern"].search(_canonicalized_source()) for rule in _rules()
    )


def test_packaged_rules_ignore_recanonicalized_raw_return_name():
    """Do not flag when the original variable is canonicalized before return."""
    assert all(
        not rule["pattern"].search(_recanonicalized_raw_return_source())
        for rule in _rules()
    )


def test_packaged_rules_ignore_decode_before_same_variable_validation():
    """Do not flag decoding that happens before all URL-path checks."""
    assert all(
        not rule["pattern"].search(_single_decode_source()) for rule in _rules()
    )


def test_packaged_rules_ignore_non_uri_segment_validation():
    """Require URL-path guard evidence instead of generic path checking."""
    assert all(
        not rule["pattern"].search(_non_uri_local_path_source())
        for rule in _rules()
    )


def test_scan_file_emits_normalized_canonicalization_finding(tmp_path):
    """Exercise the exact production scanner entrypoint on the related replay."""
    source = _raw_path_validation_source()
    findings = _scan_rule_findings(tmp_path, source)

    assert len(findings) == 1
    finding = findings[0]
    expected_line = source.splitlines().index("            path = value.strip()") + 1
    assert finding["line"] == expected_line
    assert finding["severity"] == "HIGH"
    assert finding["source"] == "appguardrail-rule"
    assert finding["file"] == "carddav_discovery.py"
    assert finding["category"] == "injection"
    assert finding["confidence"] == "high"
    assert finding["cwe"] == (
        "CWE-180 - Incorrect Behavior Order: Validate Before Canonicalize",
        "CWE-22 - Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "CWE-74 - Injection",
    )
    assert finding["owasp"] == (
        "OWASP A01:2021 - Broken Access Control",
        "OWASP A03:2021 - Injection",
    )
    assert "canonical" in finding["message"].lower()


def test_scan_file_does_not_flag_fixed_source(tmp_path):
    """Keep the source-derived negative oracle clean through production scan."""
    assert not _scan_rule_findings(tmp_path, _canonicalized_source())
