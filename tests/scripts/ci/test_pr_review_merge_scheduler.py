import pytest
from scripts.ci.pr_review_merge_scheduler import (
    _parse_pr_number,
    has_current_head_approval,
    has_current_head_changes_requested,
    split_repo,
)

def test_split_repo_valid():
    assert split_repo("owner/name") == ("owner", "name")
    assert split_repo("owner/name/extra") == ("owner", "name/extra")

def test_split_repo_invalid():
    with pytest.raises(ValueError, match="repo must be owner/name, got 'owner'"):
        split_repo("owner")

    with pytest.raises(ValueError, match="repo must be owner/name, got '/name'"):
        split_repo("/name")

    with pytest.raises(ValueError, match="repo must be owner/name, got 'owner/'"):
        split_repo("owner/")

    with pytest.raises(ValueError, match="repo must be owner/name, got '/'"):
        split_repo("/")


# --- _parse_pr_number tests ---

def test_parse_pr_number_valid_int():
    assert _parse_pr_number(1) == "1"
    assert _parse_pr_number(42) == "42"

def test_parse_pr_number_valid_str():
    assert _parse_pr_number("5") == "5"
    assert _parse_pr_number("100") == "100"

def test_parse_pr_number_rejects_bool():
    with pytest.raises(ValueError, match="bool not accepted"):
        _parse_pr_number(True)
    with pytest.raises(ValueError, match="bool not accepted"):
        _parse_pr_number(False)

def test_parse_pr_number_rejects_float():
    with pytest.raises(ValueError, match="unexpected type float"):
        _parse_pr_number(1.9)

def test_parse_pr_number_rejects_non_digit_string():
    with pytest.raises(ValueError, match="non-digit string"):
        _parse_pr_number("abc")
    with pytest.raises(ValueError, match="non-digit string"):
        _parse_pr_number("1.9")
    with pytest.raises(ValueError, match="non-digit string"):
        _parse_pr_number("-1")

def test_parse_pr_number_rejects_zero():
    with pytest.raises(ValueError, match="must be > 0"):
        _parse_pr_number(0)
    with pytest.raises(ValueError, match="must be > 0"):
        _parse_pr_number("0")

def test_parse_pr_number_rejects_negative():
    with pytest.raises(ValueError, match="must be > 0"):
        _parse_pr_number(-5)

def test_parse_pr_number_rejects_none():
    with pytest.raises(ValueError, match="unexpected type NoneType"):
        _parse_pr_number(None)


# --- has_current_head_changes_requested with github-actions[bot] ---

def _make_pr(head_oid: str, reviews: list) -> dict:
    return {
        "headRefOid": head_oid,
        "reviewDecision": "CHANGES_REQUESTED",
        "reviews": {"nodes": reviews},
        "reviewThreads": {"nodes": []},
        "statusCheckRollup": {"contexts": {"nodes": []}},
    }

def test_github_actions_bot_changes_requested_current_head():
    pr = _make_pr("abc", [
        {"state": "CHANGES_REQUESTED", "author": {"login": "github-actions[bot]"}, "commit": {"oid": "abc"}}
    ])
    assert has_current_head_changes_requested(pr)

def test_github_actions_bot_changes_requested_old_commit_not_blocking():
    pr = _make_pr("newhead", [
        {"state": "CHANGES_REQUESTED", "author": {"login": "github-actions[bot]"}, "commit": {"oid": "oldhead"}}
    ])
    assert not has_current_head_changes_requested(pr)

def test_github_actions_bot_approval_not_recognised():
    """github-actions[bot] APPROVED should not trigger auto-merge."""
    pr = _make_pr("abc", [
        {"state": "APPROVED", "author": {"login": "github-actions[bot]"}, "commit": {"oid": "abc"}}
    ])
    # reviewDecision is CHANGES_REQUESTED so the fallback won't fire either
    pr["reviewDecision"] = "REVIEW_REQUIRED"
    assert not has_current_head_approval(pr)
