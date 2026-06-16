import json
from unittest.mock import patch

from scripts.ci.opencode_review_normalize_output import iter_json_objects


def test_iter_json_objects_pure_json():
    text = '{"a": 1}'
    result = iter_json_objects(text)
    assert result == [{"a": 1}]


def test_iter_json_objects_with_prose():
    text = 'Here is the result: {"a": 1} Thanks.'
    result = iter_json_objects(text)
    assert result == [{"a": 1}]


def test_iter_json_objects_multiple_objects():
    text = '{"a": 1} and {"b": 2}'
    result = iter_json_objects(text)
    assert result == [{"a": 1}, {"b": 2}]


def test_iter_json_objects_nested():
    text = '{"a": {"b": 1}}'
    result = iter_json_objects(text)
    assert result == [{"a": {"b": 1}}]


def test_iter_json_objects_invalid():
    text = "Not a json"
    result = iter_json_objects(text)
    assert result == []


def test_iter_json_objects_partial():
    text = '{"a": '
    result = iter_json_objects(text)
    assert result == []
def test_iter_json_objects_decode_error():
    """Test that iter_json_objects handles JSONDecodeError when decoding."""
    text = "prefix { valid looking json } suffix"

    # We mock raw_decode to raise JSONDecodeError to hit the except block explicitly
    # This fulfills the 'Requires mocking the operation that throws the exception' rationale.
    with patch("json.JSONDecoder.raw_decode") as mock_raw_decode:
        mock_raw_decode.side_effect = json.JSONDecodeError("Mocked error", text, 0)

        result = iter_json_objects(text)

        assert result == []
        assert mock_raw_decode.called
