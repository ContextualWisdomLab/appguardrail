"""Contracts preventing unsupported performance claims in maintained guidance."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_fixed_tuple_classification_is_documented_as_constant_factor() -> None:
    """The two fixed output tuples must not be advertised as an asymptotic gain."""
    guidance = (ROOT / ".jules" / "bolt.md").read_text(encoding="utf-8")

    assert "O(K * N) to O(N)" not in guidance
    assert "2N to N" in guidance
    assert "constant-factor" in guidance
