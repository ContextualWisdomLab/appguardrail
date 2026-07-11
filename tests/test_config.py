"""Tests for .appguardrail.json config + severity-threshold gate."""

import pytest

from appguardrail_core.config import CONFIG_NAME, load_config
from appguardrail_core.findings import (is_deploy_blocking,
                                        severities_at_or_above)


def _write(tmp_path, text):
    (tmp_path / CONFIG_NAME).write_text(text)
    return tmp_path


def test_no_config_returns_empty(tmp_path):
    assert load_config([tmp_path]) == {}


def test_loads_fail_on_and_excludes(tmp_path):
    _write(tmp_path, '{"fail_on": "WARNING", "exclude_rules": ["a", "b"]}')
    cfg = load_config([tmp_path])
    assert cfg["fail_on"] == "WARNING"
    assert cfg["blocking_severities"] == {"CRITICAL", "HIGH", "WARNING"}
    assert cfg["exclude_rules"] == {"a", "b"}
    assert cfg["_path"].endswith(CONFIG_NAME)


def test_first_dir_wins(tmp_path):
    d1, d2 = tmp_path / "a", tmp_path / "b"
    d1.mkdir()
    d2.mkdir()
    (d1 / CONFIG_NAME).write_text('{"fail_on": "HIGH"}')
    (d2 / CONFIG_NAME).write_text('{"fail_on": "INFO"}')
    assert load_config([d1, d2])["fail_on"] == "HIGH"


@pytest.mark.parametrize(
    "text,frag",
    [
        ('{"fail_on": "BOGUS"}', "fail_on"),
        ("not json", "Invalid"),
        ("[]", "must be a JSON object"),
        ('{"exclude_rules": "x"}', "exclude_rules"),
    ],
)
def test_invalid_config_raises(tmp_path, text, frag):
    _write(tmp_path, text)
    with pytest.raises(RuntimeError) as exc:
        load_config([tmp_path])
    assert frag in str(exc.value)


def test_severities_at_or_above():
    assert severities_at_or_above("CRITICAL") == {"CRITICAL"}
    assert severities_at_or_above("HIGH") == {"CRITICAL", "HIGH"}
    assert severities_at_or_above("INFO") == {"CRITICAL", "HIGH", "WARNING", "INFO"}


def test_gate_threshold_lets_high_pass_when_critical_only():
    high = {"severity": "HIGH", "context": "app-code", "rule_id": "r"}
    assert is_deploy_blocking(high) is True  # default CRITICAL+HIGH
    assert is_deploy_blocking(high, {"CRITICAL"}) is False  # fail_on=CRITICAL
    crit = {"severity": "CRITICAL", "context": "app-code", "rule_id": "r"}
    assert is_deploy_blocking(crit, {"CRITICAL"}) is True
