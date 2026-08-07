"""Core contracts for reusable immutable scan-root path context."""

from __future__ import annotations

import os
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from appguardrail_core.scan_paths import ScanPathContext, build_scan_path_context


def test_directory_context_preserves_existing_relative_path_semantics(tmp_path: Path) -> None:
    """Directory scans classify the root once and reuse a separator-safe prefix."""
    context = build_scan_path_context(tmp_path, base_path_is_file=False)
    child = tmp_path / "src" / ".hidden.py"
    outsider = tmp_path.parent / "other" / "app.py"

    assert context.base_path == tmp_path
    assert context.resolved_base_path == tmp_path
    assert context.resolved_base_path_str == str(tmp_path)
    assert context.resolved_base_path_prefix == str(tmp_path) + os.sep
    assert not context.base_path_is_file
    assert context.relative_candidate(tmp_path) == "."
    assert context.relative_candidate(child) == os.path.join("src", ".hidden.py")
    assert context.relative_candidate(outsider) == str(outsider)


def test_single_file_context_uses_working_directory_and_filename_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A single-file scan retains the legacy working-directory and name behavior."""
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "standalone.py"
    target.write_text("print('safe')\n", encoding="utf-8")

    context = build_scan_path_context(target, base_path_is_file=True)

    assert context.resolved_base_path == tmp_path.resolve()
    assert context.base_path_is_file
    assert context.relative_candidate(target) == "standalone.py"


def test_context_is_immutable_and_rejects_invalid_builder_inputs(tmp_path: Path) -> None:
    """Callers cannot mutate cached identity or smuggle a non-Boolean classification."""
    context = build_scan_path_context(tmp_path, base_path_is_file=False)

    with pytest.raises(FrozenInstanceError):
        context.base_path_is_file = True  # type: ignore[misc]
    with pytest.raises(TypeError, match="pathlib.Path"):
        build_scan_path_context(str(tmp_path))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="Boolean"):
        build_scan_path_context(tmp_path, base_path_is_file=1)  # type: ignore[arg-type]


def test_builder_performs_one_classification_only_when_caller_has_no_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Standalone users pay one classification while batch callers pay none here."""
    calls: list[Path] = []
    original = Path.is_file

    def counted(path: Path) -> bool:
        calls.append(path)
        return original(path)

    monkeypatch.setattr(Path, "is_file", counted)

    standalone = build_scan_path_context(tmp_path)
    batch = build_scan_path_context(tmp_path, base_path_is_file=False)

    assert not standalone.base_path_is_file
    assert not batch.base_path_is_file
    assert calls == [tmp_path]


def test_context_handles_separator_boundaries_without_prefix_collision(tmp_path: Path) -> None:
    """A sibling whose name merely starts with the root is never treated as a child."""
    root = tmp_path / "repo"
    root.mkdir()
    context = build_scan_path_context(root, base_path_is_file=False)
    colliding_sibling = tmp_path / "repository" / "file.py"

    assert context.relative_candidate(colliding_sibling) == str(colliding_sibling)


def test_public_record_accepts_cross_platform_cached_strings() -> None:
    """The immutable record preserves a caller's platform-specific separator contract."""
    context = ScanPathContext(
        base_path=Path("C:/repo"),
        resolved_base_path=Path("C:/repo"),
        resolved_base_path_str=r"C:\repo",
        resolved_base_path_prefix="C:\\repo\\",
        base_path_is_file=False,
    )
    child = Path(r"C:\repo\src\app.py")

    assert context.relative_candidate(child) == r"src\app.py"
