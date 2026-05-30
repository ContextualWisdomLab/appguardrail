import unittest
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add the parent directory of scanner to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanner.cli.vibesec import cmd_init


class TestCmdInit(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for testing
        self.test_dir = tempfile.TemporaryDirectory()
        self.old_cwd = os.getcwd()
        os.chdir(self.test_dir.name)

    def tearDown(self):
        # Restore the original working directory
        os.chdir(self.old_cwd)
        self.test_dir.cleanup()

    @patch('sys.stdout', new_callable=MagicMock)
    def test_cmd_init_cursor(self, mock_stdout):
        args = MagicMock()
        args.tool = "cursor"
        args.stack = None

        cmd_init(args)

        # Verify files were created
        rules_file = Path(".cursor/rules/vibesec.md")
        checklist_file = Path("VIBESEC_CHECKLIST.md")

        self.assertTrue(rules_file.exists(), ".cursor/rules/vibesec.md should exist")
        self.assertTrue(checklist_file.exists(), "VIBESEC_CHECKLIST.md should exist")

        # Verify basic content structure
        rules_content = rules_file.read_text()
        self.assertIn("# VibeSec Security Rules", rules_content)

        # The checklist template in vibesec.py should be checked for actual content
        # I'll check for something generic or just that it's not empty
        checklist_content = checklist_file.read_text()
        self.assertTrue(len(checklist_content) > 0)

    @patch('sys.stdout', new_callable=MagicMock)
    def test_cmd_init_claude_code_new(self, mock_stdout):
        args = MagicMock()
        args.tool = "claude-code"
        args.stack = None

        cmd_init(args)

        claude_file = Path("CLAUDE.md")
        checklist_file = Path("VIBESEC_CHECKLIST.md")

        self.assertTrue(claude_file.exists())
        self.assertTrue(checklist_file.exists())

        content = claude_file.read_text()
        self.assertIn("VibeSec", content)

    @patch('sys.stdout', new_callable=MagicMock)
    def test_cmd_init_claude_code_append(self, mock_stdout):
        # Create existing CLAUDE.md without VibeSec
        Path("CLAUDE.md").write_text("Existing content")

        args = MagicMock()
        args.tool = "claude-code"
        args.stack = None

        cmd_init(args)

        content = Path("CLAUDE.md").read_text()
        self.assertIn("Existing content", content)
        self.assertIn("VibeSec", content)

    @patch('sys.stdout', new_callable=MagicMock)
    def test_cmd_init_claude_code_skip(self, mock_stdout):
        # Create existing CLAUDE.md WITH VibeSec
        Path("CLAUDE.md").write_text("Existing content with VibeSec rules")

        args = MagicMock()
        args.tool = "claude-code"
        args.stack = None

        cmd_init(args)

        content = Path("CLAUDE.md").read_text()
        self.assertEqual("Existing content with VibeSec rules", content)

    @patch('sys.stdout', new_callable=MagicMock)
    def test_cmd_init_windsurf(self, mock_stdout):
        args = MagicMock()
        args.tool = "windsurf"
        args.stack = None

        cmd_init(args)

        rules_file = Path(".windsurf/rules/vibesec.md")
        checklist_file = Path("VIBESEC_CHECKLIST.md")

        self.assertTrue(rules_file.exists())
        self.assertTrue(checklist_file.exists())

        content = rules_file.read_text()
        self.assertIn("VibeSec", content)

    @patch('sys.stdout', new_callable=MagicMock)
    def test_cmd_init_lovable(self, mock_stdout):
        args = MagicMock()
        args.tool = "lovable"
        args.stack = None

        cmd_init(args)

        checklist_file = Path("VIBESEC_CHECKLIST.md")
        self.assertTrue(checklist_file.exists())

        # Verify no other specific tool directories/files were created
        self.assertFalse(Path(".cursor").exists())
        self.assertFalse(Path("CLAUDE.md").exists())
        self.assertFalse(Path(".windsurf").exists())

    @patch('sys.stdout', new_callable=MagicMock)
    def test_cmd_init_unknown_tool(self, mock_stdout):
        args = MagicMock()
        args.tool = "invalid-tool-name"
        args.stack = None

        with self.assertRaises(SystemExit) as cm:
            cmd_init(args)

        self.assertEqual(cm.exception.code, 1)

        # Verify no files were created
        self.assertFalse(Path("VIBESEC_CHECKLIST.md").exists())
        self.assertFalse(Path(".cursor").exists())

    def test_cmd_init_supabase_stack(self):
        args = MagicMock()
        args.tool = "cursor"
        args.stack = "nextjs-supabase"

        # We need to capture the output to verify the reminder was printed
        import io
        with patch('sys.stdout', new=io.StringIO()) as fake_out:
            cmd_init(args)
            output = fake_out.getvalue()

        self.assertIn("Supabase stack detected", output)
        self.assertIn("Enable RLS on every user-data table", output)


if __name__ == '__main__':
    unittest.main()
