"""Byte-oriented fuzz target for AppGuardrail parser and path helpers."""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner.cli.appguardrail import (
    _parse_inline_list,
    _path_matches_glob,
    _sanitize_terminal_output,
)


def TestOneInput(data: bytes) -> None:
    """Exercise CLI helper parsing with arbitrary byte input."""
    text = data.decode("utf-8", errors="ignore")
    parts = text.split("\x00")
    path = parts[0] if parts else ""
    pattern = parts[1] if len(parts) > 1 else "**/*"

    _sanitize_terminal_output(text)
    _parse_inline_list(text)
    _path_matches_glob(path, pattern)


def main() -> None:
    """Run a few deterministic smoke seeds outside a fuzzing engine."""
    for seed in (b"", b"scanner\\cli\\appguardrail.py\x00**/*.py", b"\x1b[31msecret"):
        TestOneInput(seed)


if __name__ == "__main__":
    main()
