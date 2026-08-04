"""Module-entrypoint coverage for the Code Scanning drift collector."""

from __future__ import annotations

import runpy
import sys

import pytest


def test_module_entrypoint_fails_closed_without_split_tokens(monkeypatch) -> None:
    """Direct execution must reach the guarded entrypoint and reject missing tokens."""
    monkeypatch.delenv("GH_READ_TOKEN", raising=False)
    monkeypatch.delenv("GH_WRITE_TOKEN", raising=False)
    monkeypatch.setattr(sys, "argv", ["collect_code_scanning_drift.py"])
    sys.modules.pop("scripts.ci.collect_code_scanning_drift", None)

    with pytest.raises(SystemExit, match="both required"):
        runpy.run_module(
            "scripts.ci.collect_code_scanning_drift",
            run_name="__main__",
        )
