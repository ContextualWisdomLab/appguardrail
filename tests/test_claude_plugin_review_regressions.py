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


def test_file_count_budget_stops_hostile_tree_enumeration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file-count budget must bound directory-entry enumeration itself."""
    for index in range(6):
        (tmp_path / f"payload-{index}.txt").write_text("x", encoding="utf-8")

    monkeypatch.setattr(detector, "_MAX_PACKAGE_FILES", 2)
    monkeypatch.setattr(detector, "_MAX_PACKAGE_BYTES", 1024)
    original_iterdir = Path.iterdir
    enumerated = 0

    def counted_iterdir(path: Path):
        iterator = original_iterdir(path)

        def count_entries():
            nonlocal enumerated
            for entry in iterator:
                enumerated += 1
                yield entry

        return count_entries()

    monkeypatch.setattr(Path, "iterdir", counted_iterdir)

    detector._artifact_digest(tmp_path)

    assert enumerated <= detector._MAX_PACKAGE_FILES + 1


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


def test_single_file_payload_read_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One hostile file cannot force a payload read beyond the byte budget sentinel."""
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"0123456789")
    monkeypatch.setattr(detector, "_MAX_PACKAGE_BYTES", 4)

    assert detector._regular_file_bytes(payload) == b"01234"


def test_directory_entry_budget_marks_inventory_oversized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Directory-only fanout is bounded and retained as fail-closed evidence."""
    for index in range(6):
        (tmp_path / f"directory-{index}").mkdir()
    monkeypatch.setattr(detector, "_MAX_PACKAGE_FILES", 2)

    inventory = detector._build_artifact_inventory(tmp_path)

    assert inventory.oversized


def test_receipt_reuses_one_bounded_artifact_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One receipt must not independently traverse the same hostile tree repeatedly."""
    _minimal_plugin(tmp_path)
    (tmp_path / "NOTICE").write_text("Third-party notices\n", encoding="utf-8")
    original_walk = detector._walk_entries
    walks = 0

    def counted_walk(root: Path):
        nonlocal walks
        walks += 1
        return original_walk(root)

    monkeypatch.setattr(detector, "_walk_entries", counted_walk)

    detector.build_claude_plugin_scan_receipt(tmp_path)

    assert walks == 1
