import json
import pytest
from unittest.mock import patch

from scripts.ci.opencode_review_normalize_output import iter_json_objects, main, valid_control


def test_iter_json_objects_valid_json():
    # Test valid JSON string without prose
    text = '{"key": "value"}'
    result = iter_json_objects(text)
    # The current implementation will find the main json, then scan for `{`
    # and find it again.
    assert result == [{"key": "value"}, {"key": "value"}]


def test_iter_json_objects_invalid_json_with_prose():
    # Test JSON string with surrounding prose
    text = 'Here is some text: {"key": "value"} and more text.'
    result = iter_json_objects(text)
    assert result == [{"key": "value"}]


def test_iter_json_objects_json_decode_error_in_try_block():
    # Test error path where json.loads raises JSONDecodeError
    # We mock json.loads to force the exception
    text = '{"key": "value"}'
    with patch(
        "json.loads", side_effect=json.JSONDecodeError("Expecting value", "", 0)
    ):
        result = iter_json_objects(text)
        assert result == [{"key": "value"}]


def test_iter_json_objects_json_decode_error_in_loop():
    # Test error path where decoder.raw_decode raises JSONDecodeError
    # e.g., an incomplete JSON object
    text = 'Here is a broken { "key": '
    result = iter_json_objects(text)
    assert result == []


def test_valid_control_approve():
    value = {
        "head_sha": "sha123",
        "run_id": "id123",
        "run_attempt": "1",
        "result": "APPROVE",
        "reason": "Looks good",
        "summary": "Approved",
        "findings": [],
        "extra_field": "should_be_ignored"
    }
    result = valid_control(
        value,
        expected_head_sha="sha123",
        expected_run_id="id123",
        expected_run_attempt="1"
    )
    assert result == {
        "head_sha": "sha123",
        "run_id": "id123",
        "run_attempt": "1",
        "result": "APPROVE",
        "reason": "Looks good",
        "summary": "Approved",
        "findings": []
    }

def test_valid_control_request_changes():
    value = {
        "head_sha": "sha123",
        "run_id": "id123",
        "run_attempt": "1",
        "result": "REQUEST_CHANGES",
        "reason": "Has issues",
        "summary": "Needs work",
        "findings": [
            {
                "line": 42,
                "path": "file.py",
                "severity": "high",
                "title": "Bug",
                "problem": "Bad code",
                "root_cause": "Typo",
                "fix_direction": "Fix it",
                "regression_test_direction": "Test it",
                "suggested_diff": "- bad\n+ good",
                "extra": "ignore"
            }
        ]
    }
    result = valid_control(
        value,
        expected_head_sha="sha123",
        expected_run_id="id123",
        expected_run_attempt="1"
    )
    assert result is not None
    assert result["findings"] == value["findings"]

def test_valid_control_invalid_type():
    assert valid_control("not a dict", expected_head_sha="s", expected_run_id="i", expected_run_attempt="1") is None

def test_valid_control_mismatched_metadata():
    value = {
        "head_sha": "sha123",
        "run_id": "id123",
        "run_attempt": "1",
        "result": "APPROVE",
        "reason": "r",
        "summary": "s",
        "findings": []
    }

    assert valid_control(value, expected_head_sha="wrong", expected_run_id="id123", expected_run_attempt="1") is None
    assert valid_control(value, expected_head_sha="sha123", expected_run_id="wrong", expected_run_attempt="1") is None
    assert valid_control(value, expected_head_sha="sha123", expected_run_id="id123", expected_run_attempt="wrong") is None

def test_valid_control_invalid_result():
    value = {
        "head_sha": "sha",
        "run_id": "id",
        "run_attempt": "1",
        "result": "INVALID",
        "reason": "r",
        "summary": "s",
        "findings": []
    }
    assert valid_control(value, expected_head_sha="sha", expected_run_id="id", expected_run_attempt="1") is None

def test_valid_control_invalid_reason_summary():
    base = {
        "head_sha": "sha", "run_id": "id", "run_attempt": "1",
        "result": "APPROVE", "findings": []
    }

    # Missing reason
    val = dict(base, summary="s")
    assert valid_control(val, expected_head_sha="sha", expected_run_id="id", expected_run_attempt="1") is None

    # Empty reason
    val = dict(base, reason="  ", summary="s")
    assert valid_control(val, expected_head_sha="sha", expected_run_id="id", expected_run_attempt="1") is None

    # Missing summary
    val = dict(base, reason="r")
    assert valid_control(val, expected_head_sha="sha", expected_run_id="id", expected_run_attempt="1") is None

    # Empty summary
    val = dict(base, reason="r", summary="")
    assert valid_control(val, expected_head_sha="sha", expected_run_id="id", expected_run_attempt="1") is None

def test_valid_control_findings_logic():
    base = {
        "head_sha": "sha", "run_id": "id", "run_attempt": "1",
        "reason": "r", "summary": "s"
    }

    # findings not a list
    val = dict(base, result="APPROVE", findings="not a list")
    assert valid_control(val, expected_head_sha="sha", expected_run_id="id", expected_run_attempt="1") is None

    # APPROVE with findings
    val = dict(base, result="APPROVE", findings=[{}])
    assert valid_control(val, expected_head_sha="sha", expected_run_id="id", expected_run_attempt="1") is None

    # REQUEST_CHANGES without findings
    val = dict(base, result="REQUEST_CHANGES", findings=[])
    assert valid_control(val, expected_head_sha="sha", expected_run_id="id", expected_run_attempt="1") is None

def test_valid_control_invalid_findings():
    base = {
        "head_sha": "sha", "run_id": "id", "run_attempt": "1",
        "result": "REQUEST_CHANGES", "reason": "r", "summary": "s"
    }
    valid_finding = {
        "line": 1, "path": "p", "severity": "s", "title": "t",
        "problem": "p", "root_cause": "r", "fix_direction": "f",
        "regression_test_direction": "r", "suggested_diff": "s"
    }

    # Finding not a dict
    val = dict(base, findings=["not dict"])
    assert valid_control(val, expected_head_sha="sha", expected_run_id="id", expected_run_attempt="1") is None

    # Invalid line
    val = dict(base, findings=[dict(valid_finding, line=0)])
    assert valid_control(val, expected_head_sha="sha", expected_run_id="id", expected_run_attempt="1") is None
    val = dict(base, findings=[dict(valid_finding, line="1")])
    assert valid_control(val, expected_head_sha="sha", expected_run_id="id", expected_run_attempt="1") is None

    # Missing required field
    for field in ["path", "severity", "title", "problem", "root_cause", "fix_direction", "regression_test_direction", "suggested_diff"]:
        finding = dict(valid_finding)
        del finding[field]
        val = dict(base, findings=[finding])
        assert valid_control(val, expected_head_sha="sha", expected_run_id="id", expected_run_attempt="1") is None

        # Empty field
        finding = dict(valid_finding)
        finding[field] = "   "
        val = dict(base, findings=[finding])
        assert valid_control(val, expected_head_sha="sha", expected_run_id="id", expected_run_attempt="1") is None


def test_main_rejects_output_file_outside_repo(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    output_file = tmp_path / "review.json"
    output_file.write_text("{}", encoding="utf-8")

    exit_code = main(["prog", "sha123", "run123", "1", str(output_file)])

    assert exit_code == 65
    assert "outside the project root" in capsys.readouterr().err
