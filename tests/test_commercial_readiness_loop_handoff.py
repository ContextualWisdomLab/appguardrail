"""Handoff contract tests for recurring commercial-readiness work."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "ci"
    / "commercial_readiness_loop.py"
)


def _load_module():
    """Load the scheduled-loop module from the repository tree."""
    spec = importlib.util.spec_from_file_location(
        "commercial_readiness_loop_handoff",
        MODULE_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_generated_gap_requires_issue_closure_and_next_backlog_decision() -> None:
    """Each completed slice must close its issue and keep the loop self-renewing."""
    module = _load_module()

    body = module.render_gap_issue(module.COMMERCIAL_GAPS[0])

    assert "Closes" in body
    assert "COMMERCIAL_GAPS" in body
    assert "remove the completed gap" in body
    assert "next evidence-backed" in body
