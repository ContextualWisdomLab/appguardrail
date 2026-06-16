import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path("scripts/ci").resolve()))
import opencode_review_normalize_output

def test_main_oserror_on_read(capsys):
    argv = [
        "opencode_review_normalize_output.py",
        "expected_sha",
        "123",
        "1",
        "nonexistent_file.json"
    ]
    with patch("opencode_review_normalize_output.Path.read_text") as mock_read_text:
        mock_read_text.side_effect = OSError("mocked error")

        return_code = opencode_review_normalize_output.main(argv)

        assert return_code == 65

        captured = capsys.readouterr()
        assert "cannot read OpenCode output file: mocked error" in captured.err
