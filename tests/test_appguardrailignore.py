"""Tests for .appguardrailignore support."""

import subprocess
import sys
from pathlib import Path

from scanner.cli.appguardrail import _is_ignored, _load_ignore_patterns

REPO = Path(__file__).resolve().parents[1]


def test_load_patterns(tmp_path):
    (tmp_path / ".appguardrailignore").write_text(
        "# comment\n\nvendor/\n*.min.js\ndocs/generated\n", encoding="utf-8"
    )
    assert _load_ignore_patterns(tmp_path) == ["vendor", "*.min.js", "docs/generated"]


def test_load_missing_returns_empty(tmp_path):
    assert _load_ignore_patterns(tmp_path) == []


def test_is_ignored_matching(tmp_path):
    patterns = ["vendor", "*.min.js", "docs/generated"]
    root = tmp_path
    root_posix = root.as_posix()
    root_prefix = root_posix + "/" if not root_posix.endswith("/") else root_posix

    assert _is_ignored(root / "vendor" / "lib.js", root_posix, root_prefix, patterns)
    assert _is_ignored(
        root / "app" / "vendor" / "x.js", root_posix, root_prefix, patterns
    )  # anywhere
    assert _is_ignored(root / "bundle.min.js", root_posix, root_prefix, patterns)
    assert _is_ignored(
        root / "docs" / "generated" / "api.md", root_posix, root_prefix, patterns
    )
    assert not _is_ignored(root / "src" / "main.js", root_posix, root_prefix, patterns)
    assert not _is_ignored(root / "src" / "main.js", root_posix, root_prefix, [])


def test_e2e_scan_respects_ignore(tmp_path):
    app = tmp_path / "app"
    (app / "vendor").mkdir(parents=True)
    (app / "src").mkdir()
    # Assemble the fake key at runtime so GitHub push protection doesn't
    # mistake this fixture for a real Stripe secret.
    fake_key = "sk_" + "live_" + "ABCDEFGHIJKLMNOPQRSTUVWX"
    secret = f'const k = "{fake_key}";\n'
    (app / "vendor" / "lib.js").write_text(secret, encoding="utf-8")
    (app / "src" / "main.js").write_text(secret, encoding="utf-8")
    (app / ".appguardrailignore").write_text("vendor/\n", encoding="utf-8")
    out = subprocess.run(
        [
            sys.executable,
            str(REPO / "scanner" / "cli" / "appguardrail.py"),
            "scan",
            str(app),
        ],
        capture_output=True,
        text=True,
    ).stdout
    assert "vendor/lib.js" not in out
    assert "src/main.js" in out
    assert ".appguardrailignore" in out  # skip notice printed
