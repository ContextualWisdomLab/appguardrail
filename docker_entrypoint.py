#!/usr/bin/env python3
"""Launch the trusted AppGuardrail CLI from an isolated Python process."""

import sys
from pathlib import Path


def main() -> None:
    """Prepend the immutable application root before importing the CLI."""
    app_root = Path(__file__).resolve().parent
    sys.path.insert(0, str(app_root))

    from scanner.cli.appguardrail import main as cli_main

    cli_main()
    raise SystemExit(0)


if __name__ == "__main__":
    main()
