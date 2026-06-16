import json
import pytest
from unittest.mock import patch

from scripts.ci.opencode_review_normalize_output import iter_json_objects


def test_iter_json_objects_valid_json():
    # Test valid JSON string without prose.
    # iter_json_objects has two extraction passes:
    #   1. json.loads(text) succeeds and appends the object.
    #   2. A char-by-char while-loop finds the opening '{' and uses
    #      decoder.raw_decode(), appending the same object a second time.
    # Both passes succeed for a bare JSON string, so the list contains the
    # object twice. Callers are expected to tolerate duplicates; valid_control()
    # de-duplicates by returning on the first matching object.
    text = '{"key": "value"}'
    result = iter_json_objects(text)
    assert result == [{"key": "value"}, {"key": "value"}]


def test_iter_json_objects_invalid_json_with_prose():
    # Test JSON string with surrounding prose.
    # json.loads(text) fails because of the prose, so the first pass yields
    # nothing. The while-loop fallback scans char-by-char, finds '{', and
    # decoder.raw_decode() successfully extracts the embedded JSON object.
    text = 'Here is some text: {"key": "value"} and more text.'
    result = iter_json_objects(text)
    assert result == [{"key": "value"}]


def test_iter_json_objects_json_decode_error_in_try_block():
    # Test the fallback behavior when json.loads raises JSONDecodeError.
    # iter_json_objects has two extraction passes:
    #   1. json.loads(text) — mocked here to raise JSONDecodeError, so the
    #      first pass is skipped (the exception is caught and ignored).
    #   2. The char-by-char while-loop uses decoder.raw_decode() on the
    #      JSONDecoder instance, which is NOT mocked, so it still successfully
    #      parses the JSON and appends the object.
    # This verifies that the while-loop fallback path works independently of
    # the json.loads fast path.
    text = '{"key": "value"}'
    with patch(
        "json.loads", side_effect=json.JSONDecodeError("Expecting value", "", 0)
    ):
        result = iter_json_objects(text)
        assert result == [{"key": "value"}]


def test_iter_json_objects_json_decode_error_in_loop():
    # Test error path where decoder.raw_decode raises JSONDecodeError
    # e.g., an incomplete JSON object. Both passes fail, so the result is empty.
    text = 'Here is a broken { "key": '
    result = iter_json_objects(text)
    assert result == []
