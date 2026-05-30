import pytest
from pathlib import Path
import sys

# Add scanner to python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.cli.vibesec import cmd_init

class Args:
    def __init__(self, tool="cursor", stack=None):
        self.tool = tool
        self.stack = stack

def test_cmd_init_cursor(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cmd_init(Args(tool="cursor"))

    assert (tmp_path / ".cursor" / "rules" / "vibesec.md").exists()
    assert (tmp_path / "VIBESEC_CHECKLIST.md").exists()

    captured = capsys.readouterr()
    assert "✅ VibeSec initialized successfully!" in captured.out
    assert ".cursor/rules/vibesec.md" in captured.out

def test_cmd_init_claude_code_new(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cmd_init(Args(tool="claude-code"))

    assert (tmp_path / "CLAUDE.md").exists()
    assert (tmp_path / "VIBESEC_CHECKLIST.md").exists()

def test_cmd_init_claude_code_append(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    claude_file = tmp_path / "CLAUDE.md"
    claude_file.write_text("Existing rules\n")

    cmd_init(Args(tool="claude-code"))

    content = claude_file.read_text()
    assert "Existing rules" in content
    # Should append VibeSec rules
    assert len(content.splitlines()) > 1
    assert "CLAUDE.md (appended)" in capsys.readouterr().out

def test_cmd_init_claude_code_skip(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    claude_file = tmp_path / "CLAUDE.md"
    claude_file.write_text("VibeSec existing rules\n")

    cmd_init(Args(tool="claude-code"))

    content = claude_file.read_text()
    assert content == "VibeSec existing rules\n"
    assert "CLAUDE.md already contains VibeSec rules — skipping." in capsys.readouterr().out

def test_cmd_init_windsurf(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cmd_init(Args(tool="windsurf"))

    assert (tmp_path / ".windsurf" / "rules" / "vibesec.md").exists()
    assert (tmp_path / "VIBESEC_CHECKLIST.md").exists()
    assert ".windsurf/rules/vibesec.md" in capsys.readouterr().out

def test_cmd_init_lovable(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cmd_init(Args(tool="lovable"))

    assert not (tmp_path / ".lovable").exists() # Checking only checklist created
    assert (tmp_path / "VIBESEC_CHECKLIST.md").exists()
    assert "VIBESEC_CHECKLIST.md" in capsys.readouterr().out

def test_cmd_init_unknown_tool(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit) as excinfo:
        cmd_init(Args(tool="invalid-tool"))

    assert excinfo.value.code == 1

    captured = capsys.readouterr()
    assert "Unknown tool: invalid-tool" in captured.out
    assert "Supported tools: cursor, claude-code, windsurf, lovable" in captured.out

def test_cmd_init_supabase_stack(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cmd_init(Args(stack="nextjs-supabase"))

    captured = capsys.readouterr()
    assert "Supabase stack detected. Quick reminders:" in captured.out
    assert "Enable RLS on every user-data table" in captured.out
