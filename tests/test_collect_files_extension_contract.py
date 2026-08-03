"""Regression tests for fast file-extension extraction during collection."""

import os

from scanner.cli.appguardrail import SKIP_EXTENSIONS, _collect_files


def test_collect_files_matches_splitext_for_dotfiles_and_skipped_extensions(tmp_path):
    """The string fast path must preserve ``os.path.splitext`` semantics."""
    names = {
        ".cshrc",
        "....jpg",
        ".foo.bar",
        "ordinary.jpg",
        "PHOTO.JPG",
        "archive.tar.gz",
        "no-extension",
        "trailing.",
    }
    for name in names:
        (tmp_path / name).touch()

    collected = {path.name for path in _collect_files(tmp_path)}
    expected = {
        name
        for name in names
        if os.path.splitext(name)[1].lower() not in SKIP_EXTENSIONS
    }

    assert collected == expected
    assert "....jpg" in collected
    assert ".cshrc" in collected
    assert "ordinary.jpg" not in collected
