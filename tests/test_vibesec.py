from pathlib import Path
from unittest.mock import MagicMock
from scanner.cli.vibesec import _scan_file

def test_scan_file_error_handling():
    """Test that _scan_file handles OSError and PermissionError by returning an empty list."""
    mock_file = MagicMock(spec=Path)
    mock_base = MagicMock(spec=Path)

    # Test PermissionError
    mock_file.read_text.side_effect = PermissionError("Permission denied")
    assert _scan_file(mock_file, mock_base) == []

    # Test OSError
    mock_file.read_text.side_effect = OSError("OS error")
    assert _scan_file(mock_file, mock_base) == []
