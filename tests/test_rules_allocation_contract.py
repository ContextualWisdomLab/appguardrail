"""Allocation contracts for rule-reference hot paths."""

from types import CodeType

from appguardrail_core.rules import _merge_references, extract_public_references


def _nested_code_names(function) -> set[str]:
    """Return nested code-object names compiled into one Python function."""
    return {
        item.co_name
        for item in function.__code__.co_consts
        if isinstance(item, CodeType)
    }


def test_reference_hot_paths_do_not_allocate_generator_frames() -> None:
    """Avoid generator-frame allocation in the two per-finding dedupe paths."""
    assert "<genexpr>" not in _nested_code_names(extract_public_references)
    assert "<genexpr>" not in _nested_code_names(_merge_references)
