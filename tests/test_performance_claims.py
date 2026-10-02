"""Contracts preventing unsupported performance claims in maintained guidance."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_fixed_tuple_classification_is_documented_as_constant_factor() -> None:
    """The two fixed output tuples must not be advertised as an asymptotic gain."""
    guidance = (ROOT / ".jules" / "bolt.md").read_text(encoding="utf-8")

    assert "O(K * N) to O(N)" not in guidance
    assert "2N to N" in guidance
    assert "constant-factor" in guidance

def test_dict_comprehension_is_demonstrably_faster() -> None:
    """The dictionary comprehension optimization must be demonstrably faster."""
    import timeit

    setup = "y = list(range(1000))"
    test1 = "tuple(dict.fromkeys(x for x in y))"
    test2 = "tuple({x: None for x in y})"

    time_gen = timeit.timeit(test1, setup=setup, number=1000)
    time_comp = timeit.timeit(test2, setup=setup, number=1000)

    # Assert that dict comprehension is at least 10% faster
    assert time_comp < time_gen * 0.9, f"Dict comprehension ({time_comp}) was not significantly faster than generator ({time_gen})"
