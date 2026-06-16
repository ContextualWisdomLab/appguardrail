import json
from unittest.mock import patch

from scripts.ci.opencode_review_normalize_output import iter_json_objects, main


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

        return_code = main(argv)

    assert return_code == 65

    captured = capsys.readouterr()
    assert "cannot read OpenCode output file: mocked error" in captured.err
