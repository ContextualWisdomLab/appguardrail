"""Docstring contract for the GitHub Actions source-evidence module."""

from __future__ import annotations

import ast
from pathlib import Path

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "appguardrail_core"
    / "github_actions_evidence.py"
)


def test_every_module_class_function_and_method_has_a_docstring():
    """Require complete explanatory docstrings for every shipped symbol."""
    module = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    missing: list[str] = []

    if not ast.get_docstring(module, clean=False):
        missing.append("<module>")

    for node in ast.walk(module):
        if not isinstance(
            node,
            (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            continue
        if not ast.get_docstring(node, clean=False):
            missing.append(f"{node.name}@{node.lineno}")

    assert missing == [], "Missing shipped-symbol docstrings: " + ", ".join(missing)
