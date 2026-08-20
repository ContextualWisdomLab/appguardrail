"""Behavior contracts for AST-backed Python shell-call detection."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from appguardrail_core.python_shell_detector import (
    PYTHON_COMMAND_INJECTION_MESSAGE,
    PythonShellCall,
    find_python_shell_calls,
)
from scanner.cli.appguardrail import _scan_file


@pytest.mark.parametrize(
    ("source", "expected_api", "expected_line"),
    [
        (
            "import os\nos.system(user_input)\n",
            "os.system",
            2,
        ),
        (
            "import os as operating_system\noperating_system.popen(command)\n",
            "os.popen",
            2,
        ),
        (
            "from os import system as invoke\ninvoke(user_input)\n",
            "os.system",
            2,
        ),
        (
            "import subprocess\n"
            "subprocess.run(build(one(two(user_input))), shell=True)\n",
            "subprocess.run",
            2,
        ),
        (
            "import subprocess as sp\nsp.check_output(command, shell=True)\n",
            "subprocess.check_output",
            2,
        ),
        (
            "from subprocess import check_call as invoke\n"
            "invoke(command, shell=True)\n",
            "subprocess.check_call",
            2,
        ),
        (
            "import subprocess\n\n"
            "def execute():\n"
            "    subprocess.Popen(command, shell=True)\n",
            "subprocess.Popen",
            4,
        ),
        (
            "def execute():\n"
            "    import subprocess as child\n"
            "    child.call(command, shell=True)\n",
            "subprocess.call",
            3,
        ),
    ],
)
def test_find_python_shell_calls_resolves_supported_imports_and_aliases(
    source: str,
    expected_api: str,
    expected_line: int,
) -> None:
    """Resolve direct and aliased shell APIs without a regex nesting limit."""
    calls = find_python_shell_calls(source)

    assert calls == (
        PythonShellCall(
            line=expected_line,
            column=0 if expected_line == 2 else 4,
            api=expected_api,
            snippet=source.splitlines()[expected_line - 1].strip()[:120],
        ),
    )


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\nsubprocess.run(['id'])\n",
        "import subprocess\nsubprocess.call(command, shell=False)\n",
        "import subprocess\nenabled = True\nsubprocess.run(command, shell=enabled)\n",
        "runner.run(command, shell=True)\n",
        "text = 'os.system(user_input)'\n",
        "# subprocess.run(command, shell=True)\n",
        "import os\nos = safe_os\nos.system(user_input)\n",
        "import subprocess as sp\nsp = safe_runner\nsp.run(command, shell=True)\n",
        "from subprocess import run\nrun = safe_runner\nrun(command, shell=True)\n",
        "import subprocess\ndef execute(subprocess):\n    subprocess.run(command, shell=True)\n",
        (
            "import subprocess\n"
            "def execute():\n"
            "    subprocess.run(command, shell=True)\n"
            "    subprocess = safe_runner\n"
        ),
        (
            "import subprocess\n"
            "[subprocess.run(command, shell=True) for subprocess in runners]\n"
        ),
    ],
)
def test_find_python_shell_calls_ignores_non_authoritative_bindings(source: str) -> None:
    """Ignore strings, comments, non-shell calls, and names shadowing imports."""
    assert find_python_shell_calls(source) == ()


def test_find_python_shell_calls_returns_ordered_distinct_calls() -> None:
    """Return one immutable result per parsed call in source order."""
    source = (
        "import os\n"
        "import subprocess\n"
        "os.popen(first)\n"
        "subprocess.check_output(second, shell=True)\n"
    )

    calls = find_python_shell_calls(source)

    assert [(call.line, call.api) for call in calls] == [
        (3, "os.popen"),
        (4, "subprocess.check_output"),
    ]
    assert calls[0].snippet == "os.popen(first)"
    assert calls[1].snippet == "subprocess.check_output(second, shell=True)"


@pytest.mark.parametrize(
    "source",
    [
        "import subprocess\nsubprocess.run(command, shell=True\n",
        "def broken(:\n",
        None,
    ],
)
def test_find_python_shell_calls_fails_closed_on_unparseable_source(
    source: str | None,
) -> None:
    """Treat malformed or non-text work-in-progress input as no proven call."""
    assert find_python_shell_calls(source) == ()  # type: ignore[arg-type]


def test_scanner_emits_one_normalized_ast_finding(tmp_path: Path) -> None:
    """Integrate alias-aware AST evidence into the production file scanner."""
    target = tmp_path / "handler.py"
    target.write_text(
        "import subprocess as child\n"
        "child.run(build_command(user_input), shell=True)\n",
        encoding="utf-8",
    )

    matches = [
        finding
        for finding in _scan_file(target, tmp_path)
        if finding["rule_id"] == "python-command-injection"
    ]

    assert len(matches) == 1
    assert matches[0]["source"] == "appguardrail-python-ast"
    assert matches[0]["severity"] == "CRITICAL"
    assert matches[0]["category"] == "injection"
    assert matches[0]["line"] == 2
    assert matches[0]["message"] == PYTHON_COMMAND_INJECTION_MESSAGE


def test_scanner_keeps_regex_rules_beside_ast_findings(tmp_path: Path) -> None:
    """Preserve unrelated Python regex findings when the AST detector runs."""
    target = tmp_path / "mixed.py"
    target.write_text(
        "import os\n"
        'password = "secret123"\n'
        "os.system(user_input)\n",
        encoding="utf-8",
    )

    rule_ids = [finding["rule_id"] for finding in _scan_file(target, tmp_path)]

    assert rule_ids.count("python-command-injection") == 1
    assert "hardcoded-password" in rule_ids


def test_detector_module_has_complete_docstrings() -> None:
    """Require module, class, function, and method documentation in the detector."""
    module_path = (
        Path(__file__).resolve().parents[1]
        / "appguardrail_core"
        / "python_shell_detector.py"
    )
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    undocumented = []
    for node in ast.walk(tree):
        if isinstance(
            node,
            (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
        ) and not ast.get_docstring(node):
            undocumented.append(getattr(node, "name", "<module>"))

    assert undocumented == []
