import json
from unittest.mock import patch

from scripts.ci.opencode_review_normalize_output import iter_json_objects


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
