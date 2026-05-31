import unittest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from scanner.cli.vibesec import _collect_files, _scan_file


def test_scan_file_error_handling():
    """Test that _scan_file handles OSError and PermissionError by returning an empty list."""
    mock_file = MagicMock(spec=Path)
    mock_base = MagicMock(spec=Path)

    mock_file.read_text.side_effect = PermissionError("Permission denied")
    assert _scan_file(mock_file, mock_base) == []

    mock_file.read_text.side_effect = OSError("OS error")
    assert _scan_file(mock_file, mock_base) == []


class TestVibeSecCollectFiles(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)

        (self.base_path / "src").mkdir()
        (self.base_path / "src" / "main.py").touch()
        (self.base_path / "src" / "utils.js").touch()
        (self.base_path / "README.md").touch()

        (self.base_path / "node_modules").mkdir()
        (self.base_path / "node_modules" / "index.js").touch()

        (self.base_path / ".git").mkdir()
        (self.base_path / ".git" / "config").touch()

        (self.base_path / "src" / "image.png").touch()
        (self.base_path / "package.lock").touch()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_collect_files(self):
        collected_files = list(_collect_files(self.base_path))
        collected_rel_paths = {f.relative_to(self.base_path).as_posix() for f in collected_files}

        expected_paths = {
            "src/main.py",
            "src/utils.js",
            "README.md",
        }

        self.assertEqual(collected_rel_paths, expected_paths)
        self.assertNotIn("node_modules/index.js", collected_rel_paths)
        self.assertNotIn(".git/config", collected_rel_paths)
        self.assertNotIn("src/image.png", collected_rel_paths)
        self.assertNotIn("package.lock", collected_rel_paths)
