"""Integrity contract for the canonical buyer-facing Gap baseline."""

import hashlib
from pathlib import Path

import pytest


BASELINE_PATH = Path("docs/product-technical-gap-baseline.md")
HISTORY_PATH = Path("docs/product-technical-gap-baseline-history-6d6d7749.md")
HISTORY_BLOB = "1953b92c6c6fcfbe9a30e2b78094c214c18e6fe6"


def test_product_gap_baseline_is_utf8_markdown_with_retained_history() -> None:
    """Reject binary corruption or loss of the canonical history binding."""
    try:
        baseline = BASELINE_PATH.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        pytest.fail(f"{BASELINE_PATH} is not UTF-8 Markdown: {exc}")

    assert baseline.startswith("# AppGuardrail product and technical gap baseline")
    assert "## Technical / TRD gaps" in baseline
    assert HISTORY_BLOB in baseline
    assert "\\x00" not in baseline

    history = HISTORY_PATH.read_bytes()
    history_blob = hashlib.sha1(
        b"blob " + str(len(history)).encode("ascii") + b"\\0" + history,
        usedforsecurity=False,
    ).hexdigest()
    assert history_blob == HISTORY_BLOB


def test_product_gap_baseline_tracks_public_readme_and_license_lanes() -> None:
    """Keep the canonical register bound to the active public-surface writers."""
    baseline = BASELINE_PATH.read_text(encoding="utf-8")

    assert "## Public README, package-registry, and license evidence" in baseline
    assert "#1077" in baseline
    assert "#1253" in baseline
