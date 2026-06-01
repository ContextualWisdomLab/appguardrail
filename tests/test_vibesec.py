import unittest
import argparse
import os
import tempfile
from unittest.mock import patch, MagicMock
from scanner.cli import vibesec

class TestVibeSecCLI(unittest.TestCase):

    def test_init_cursor(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            original_dir = os.getcwd()
            os.chdir(tmpdir)
            try:
                args = argparse.Namespace(tool='cursor', stack=None)
                vibesec.init(args)
                self.assertTrue(os.path.exists('.cursor/rules/vibesec.md'))
            finally:
                os.chdir(original_dir)

    def test_init_claude_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            original_dir = os.getcwd()
            os.chdir(tmpdir)
            try:
                args = argparse.Namespace(tool='claude-code', stack=None)
                vibesec.init(args)
                self.assertTrue(os.path.exists('CLAUDE.md'))
            finally:
                os.chdir(original_dir)

    def test_init_stack(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            original_dir = os.getcwd()
            os.chdir(tmpdir)
            try:
                args = argparse.Namespace(tool=None, stack='nextjs-supabase')
                vibesec.init(args)
                self.assertTrue(os.path.exists('VIBESEC_CHECKLIST.md'))
            finally:
                os.chdir(original_dir)

    @patch('scanner.cli.vibesec.load_rules')
    def test_scan_no_findings(self, mock_load_rules):
        mock_load_rules.return_value = [
            {"pattern": "SUPER_SECRET", "message": "Secret found", "severity": "HIGH"}
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, 'safe.js'), 'w') as f:
                f.write('console.log("hello world");')

            args = argparse.Namespace(path=tmpdir)

            # Should not exit or throw
            try:
                vibesec.scan(args)
            except SystemExit:
                self.fail("scan() raised SystemExit unexpectedly")

    @patch('scanner.cli.vibesec.load_rules')
    def test_scan_with_findings(self, mock_load_rules):
        mock_load_rules.return_value = [
            {"pattern": "SUPER_SECRET", "message": "Secret found", "severity": "HIGH"}
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, 'danger.js'), 'w') as f:
                f.write('const key = "SUPER_SECRET";')

            args = argparse.Namespace(path=tmpdir)

            with self.assertRaises(SystemExit) as cm:
                vibesec.scan(args)
            self.assertEqual(cm.exception.code, 1)

if __name__ == '__main__':
    unittest.main()
