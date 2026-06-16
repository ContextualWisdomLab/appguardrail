import json
import pytest
from unittest.mock import patch

import sys
from pathlib import Path

# Add project root to path so we can import scripts
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from scripts.ci.opencode_review_normalize_output import iter_json_objects


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
