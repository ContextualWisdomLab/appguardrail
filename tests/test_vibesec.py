import unittest
import tempfile
import os
from pathlib import Path
from scanner.cli.vibesec import _collect_files

class TestVibeSecCollectFiles(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)

        # Create some allowed directories and files
        (self.base_path / "src").mkdir()
        (self.base_path / "src" / "main.py").touch()
        (self.base_path / "src" / "utils.js").touch()
        (self.base_path / "README.md").touch()

        # Create excluded directory (e.g., node_modules) and a file inside
        (self.base_path / "node_modules").mkdir()
        (self.base_path / "node_modules" / "index.js").touch()

        # Create hidden directory (e.g., .git) and a file inside
        (self.base_path / ".git").mkdir()
        (self.base_path / ".git" / "config").touch()

        # Create allowed file but with excluded extension (e.g., image.png)
        (self.base_path / "src" / "image.png").touch()
        (self.base_path / "package.lock").touch() # Note: .lock is excluded

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_collect_files(self):
        # Call the function
        collected_files = list(_collect_files(self.base_path))

        # Extract relative paths for easier comparison
        collected_rel_paths = {f.relative_to(self.base_path).as_posix() for f in collected_files}

        # Expected paths
        expected_paths = {
            "src/main.py",
            "src/utils.js",
            "README.md",
        }

        # Assertions
        self.assertEqual(collected_rel_paths, expected_paths)

        # Explicit checks for excluded files
        self.assertNotIn("node_modules/index.js", collected_rel_paths)
        self.assertNotIn(".git/config", collected_rel_paths)
        self.assertNotIn("src/image.png", collected_rel_paths)
        self.assertNotIn("package.lock", collected_rel_paths)

if __name__ == "__main__":
    unittest.main()
