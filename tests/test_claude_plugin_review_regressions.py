"""Regression locks for current Claude-plugin review findings."""

from __future__ import annotations

from pathlib import Path

import pytest

from appguardrail_core import claude_plugin_detector as detector


def _minimal_plugin(root: Path) -> None:
    """Create the minimum package shape required by the package scanner."""
    plugin_dir = root / ".claude-plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "plugin.json").write_text("{}\n", encoding="utf-8")


def test_notice_file_satisfies_declared_license_evidence(tmp_path: Path) -> None:
    """NOTICE-only packages must not be reported as missing license evidence."""
    _minimal_plugin(tmp_path)
    (tmp_path / "NOTICE").write_text("Third-party notices\n", encoding="utf-8")

    hits = detector.scan_claude_plugin_package(tmp_path)

    assert all(hit.rule_id != "claude-plugin-license-missing" for hit in hits)
    assert "NOTICE" in detector._license_summary(tmp_path)


def test_file_count_budget_stops_hostile_tree_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The digest must stop reading after crossing the bounded file-count budget."""
    for index in range(6):
        (tmp_path / f"payload-{index}.txt").write_text("x", encoding="utf-8")

    monkeypatch.setattr(detector, "_MAX_PACKAGE_FILES", 2)
    monkeypatch.setattr(detector, "_MAX_PACKAGE_BYTES", 1024)
    original = detector._regular_file_bytes
    reads = 0

    def counted_read(path: Path) -> bytes:
        nonlocal reads
        reads += 1
        return original(path)

    monkeypatch.setattr(detector, "_regular_file_bytes", counted_read)

    _, file_count, _ = detector._artifact_digest(tmp_path)

    assert file_count > detector._MAX_PACKAGE_FILES
    assert reads <= detector._MAX_PACKAGE_FILES + 1


def test_byte_budget_stops_hostile_tree_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The digest must stop reading once the bounded byte budget is crossed."""
    for index in range(6):
        (tmp_path / f"payload-{index}.txt").write_bytes(b"abc")

    monkeypatch.setattr(detector, "_MAX_PACKAGE_FILES", 100)
    monkeypatch.setattr(detector, "_MAX_PACKAGE_BYTES", 4)
    original = detector._regular_file_bytes
    reads = 0

    def counted_read(path: Path) -> bytes:
        nonlocal reads
        reads += 1
        return original(path)

    monkeypatch.setattr(detector, "_regular_file_bytes", counted_read)

    _, _, scanned_byte_count = detector._artifact_digest(tmp_path)

    assert scanned_byte_count > detector._MAX_PACKAGE_BYTES
    assert reads <= 2
