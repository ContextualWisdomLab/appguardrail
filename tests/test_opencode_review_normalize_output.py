import json
from unittest.mock import patch

from scripts.ci import opencode_review_normalize_output
from scripts.ci.opencode_review_normalize_output import iter_json_objects


def test_main_oserror_on_read(capsys):
    argv = [
        "opencode_review_normalize_output.py",
        "expected_sha",
        "123",
        "1",
        "nonexistent_file.json",
    ]

    with patch("scripts.ci.opencode_review_normalize_output.Path.read_text") as mock_read_text:
        mock_read_text.side_effect = OSError("mocked error")

        return_code = opencode_review_normalize_output.main(argv)

    assert return_code == 65

    captured = capsys.readouterr()
    assert "cannot read OpenCode output file: mocked error" in captured.err


def test_iter_json_objects_valid_json():
    # Test valid JSON string without prose.
    # iter_json_objects has two extraction passes:
    #   1. json.loads fast path (succeeds for the full string)
    #   2. char-by-char while-loop using decoder.raw_decode (also finds the object)
    # A bare JSON string therefore legitimately produces two identical objects.
    text = '{"key": "value"}'
    result = iter_json_objects(text)
    assert result == [{"key": "value"}, {"key": "value"}]


def test_iter_json_objects_invalid_json_with_prose():
    # Test JSON string with surrounding prose.
    # json.loads fails on the full string, so only the char-by-char pass runs.
    text = 'Here is some text: {"key": "value"} and more text.'
    result = iter_json_objects(text)
    assert result == [{"key": "value"}]


def test_iter_json_objects_json_decode_error_in_try_block():
    # Test error path where json.loads raises JSONDecodeError (first pass fails).
    # Only json.loads is mocked; decoder.raw_decode on the JSONDecoder instance is
    # not mocked, so the char-by-char fallback loop still successfully parses and
    # returns the object.
    text = '{"key": "value"}'
    with patch(
        "json.loads", side_effect=json.JSONDecodeError("Expecting value", "", 0)
    ):
        result = iter_json_objects(text)
        assert result == [{"key": "value"}]


def test_iter_json_objects_json_decode_error_in_loop():
    # Test error path where decoder.raw_decode raises JSONDecodeError,
    # e.g. an incomplete JSON object — both passes fail, so we get an empty list.
    text = 'Here is a broken { "key": '
    result = iter_json_objects(text)
    assert result == []
