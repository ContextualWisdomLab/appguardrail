"""Contracts for precomputed scan-root path context passed into file scanning."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from scanner.cli.appguardrail import ScanArgs, cmd_scan


def test_cmd_scan_passes_exact_precomputed_path_context(tmp_path: Path) -> None:
    """Every file receives one shared resolved root, prefix, and root-kind decision."""
    files = [tmp_path / "first.py", tmp_path / "second.py"]
    for file_path in files:
        file_path.write_text("print('safe')\n", encoding="utf-8")
    observed: list[tuple[Path, Path, Path, str, str, bool]] = []

    def fake_collect_files(_base_path: Path):
        """Yield deterministic files without changing the scan-root contract."""
        yield from files

    def fake_scan_file(
        file_path: Path,
        base_path: Path,
        resolved_base_path: Path,
        resolved_base_path_str: str,
        resolved_base_path_prefix: str,
        base_path_is_file: bool,
    ) -> list[dict[str, object]]:
        """Capture every precomputed argument instead of swallowing it."""
        observed.append(
            (
                file_path,
                base_path,
                resolved_base_path,
                resolved_base_path_str,
                resolved_base_path_prefix,
                base_path_is_file,
            )
        )
        return []

    with (
        patch(
            "scanner.cli.appguardrail._collect_files", side_effect=fake_collect_files
        ),
        patch("scanner.cli.appguardrail._scan_file", side_effect=fake_scan_file),
    ):
        assert cmd_scan(ScanArgs(tmp_path)) == 0

    expected_root = tmp_path.resolve()
    expected_prefix = str(expected_root)
    if not expected_prefix.endswith(os.sep):
        expected_prefix += os.sep
    assert [item[0] for item in observed] == files
    assert len(observed) == len(files)
    assert all(item[1] == expected_root for item in observed)
    assert all(item[2] == expected_root for item in observed)
    assert all(item[3] == str(expected_root) for item in observed)
    assert all(item[4] == expected_prefix for item in observed)
    assert all(item[5] is False for item in observed)
