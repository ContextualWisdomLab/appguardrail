"""Scanner integration and operation-count contracts for issue 893."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from appguardrail_core.scan_paths import ScanPathContext
from scanner.cli import appguardrail as cli


class _StringSubclass(str):
    """Exercise public string contracts without collapsing subclass identity."""


def _scan_args(path: Path) -> SimpleNamespace:
    """Return the minimum deterministic zero-external-engine scan arguments."""
    return SimpleNamespace(
        path=str(path),
        trivy=False,
        external="off",
        bandit=False,
        ruff=False,
        semgrep=False,
        semgrep_config=None,
        zap_baseline=None,
        findings_json=None,
        codegraph=False,
    )


def test_cmd_scan_reuses_one_exact_context_for_large_stream(tmp_path: Path) -> None:
    """Two thousand files reuse one immutable context instead of reclassifying the root."""
    files = tuple(tmp_path / "src" / f"module_{index}.py" for index in range(2_000))
    observed: list[tuple[Path, Path, ScanPathContext]] = []

    def fake_collect_files(base_path: Path):
        assert base_path == tmp_path.resolve()
        yield from files

    def fake_scan_file(
        file_path: Path,
        base_path: Path,
        *,
        path_context: ScanPathContext,
    ) -> list[dict[str, object]]:
        observed.append((file_path, base_path, path_context))
        return []

    with (
        patch("scanner.cli.appguardrail._collect_files", side_effect=fake_collect_files),
        patch("scanner.cli.appguardrail._scan_file", side_effect=fake_scan_file),
    ):
        assert cli.cmd_scan(_scan_args(tmp_path)) == 0

    assert len(observed) == len(files)
    first_context = observed[0][2]
    assert all(context is first_context for _, _, context in observed)
    assert all(base_path == tmp_path.resolve() for _, base_path, _ in observed)
    assert first_context.base_path == tmp_path.resolve()
    assert first_context.resolved_base_path == tmp_path.resolve()
    assert first_context.resolved_base_path_str == str(tmp_path.resolve())
    assert first_context.resolved_base_path_prefix == str(tmp_path.resolve()) + os.sep
    assert not first_context.base_path_is_file


def test_cmd_scan_classifies_root_once_and_never_inside_file_calls(tmp_path: Path) -> None:
    """The deterministic operation-count benchmark is one root classification per scan."""
    files = tuple(tmp_path / f"file_{index}.py" for index in range(10_000))
    classification_calls: list[Path] = []
    original_is_file = Path.is_file

    def counted_is_file(path: Path) -> bool:
        if path == tmp_path.resolve():
            classification_calls.append(path)
        return original_is_file(path)

    with (
        patch.object(Path, "is_file", counted_is_file),
        patch("scanner.cli.appguardrail._collect_files", return_value=iter(files)),
        patch("scanner.cli.appguardrail._scan_file", return_value=[]),
    ):
        assert cli.cmd_scan(_scan_args(tmp_path)) == 0

    assert classification_calls == [tmp_path.resolve()]


def test_scan_file_standalone_fallback_builds_context_once(tmp_path: Path) -> None:
    """Direct callers retain a single safe context build when no batch context exists."""
    target = tmp_path / "safe.unknown"
    target.write_text("safe\n", encoding="utf-8")
    context = ScanPathContext(
        base_path=tmp_path,
        resolved_base_path=tmp_path,
        resolved_base_path_str=str(tmp_path),
        resolved_base_path_prefix=str(tmp_path) + os.sep,
        base_path_is_file=False,
    )

    with patch(
        "scanner.cli.appguardrail.build_scan_path_context",
        return_value=context,
    ) as build_context:
        assert cli._scan_file(target, tmp_path) == []

    build_context.assert_called_once_with(tmp_path)


def test_string_subclasses_preserve_language_and_display_contracts() -> None:
    """Allocation-light paths still treat every str subclass as text, never as Path."""
    value = _StringSubclass(r"src\nested\module.py")

    assert cli.detect_language_axes([value]) == {"python"}
    assert cli._display_path(value) == "src/nested/module.py"
