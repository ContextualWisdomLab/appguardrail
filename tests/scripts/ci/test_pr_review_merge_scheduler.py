import argparse

import pytest
from scripts.ci.pr_review_merge_scheduler import (
    _parse_pr_number,
    dispatch_opencode_review,
    enable_auto_merge,
    inspect_pr,
    run,
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


def test_parse_pr_number_accepts_int_and_ascii_digits():
    assert _parse_pr_number(17) == "17"
    assert _parse_pr_number("98") == "98"
    assert _parse_pr_number("001") == "1"


@pytest.mark.parametrize(
    "raw",
    [
        True,
        False,
        0,
        -1,
        1.5,
        "0",
        "-1",
        "1.5",
        "--help",
        "１２",
        None,
    ],
)
def test_parse_pr_number_rejects_unsafe_values(raw):
    with pytest.raises(ValueError, match="Invalid PR number"):
        _parse_pr_number(raw)


def test_enable_auto_merge_validates_pr_number_before_dry_run():
    with pytest.raises(ValueError, match="Invalid PR number"):
        enable_auto_merge("owner/repo", {"number": "--help", "headRefOid": "abc"}, dry_run=True)


def test_dispatch_review_validates_pr_number_before_dry_run():
    with pytest.raises(ValueError, match="Invalid PR number"):
        dispatch_opencode_review(
            "owner/repo",
            "OpenCode Review",
            {"number": "--help"},
            dry_run=True,
        )


def test_inspect_pr_validates_pr_number_before_decision():
    with pytest.raises(ValueError, match="Invalid PR number"):
        inspect_pr(
            "owner/repo",
            {"number": "--help"},
            dry_run=True,
            trigger_reviews=False,
            enable_auto_merge_flag=False,
            workflow="OpenCode Review",
            base_branch="develop",
        )


def test_run_rejects_non_string_argument():
    with pytest.raises(ValueError, match="must be a string"):
        run(["echo", 123])  # type: ignore[list-item]


def test_run_rejects_non_printable_argument():
    with pytest.raises(ValueError, match="non-printable characters"):
        run(["echo", "hello\x00world"])


def test_run_accepts_valid_arguments(monkeypatch):
    import subprocess

    completed = subprocess.CompletedProcess(args=["echo", "hi"], returncode=0, stdout="hi\n", stderr="")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: completed)
    result = run(["echo", "hi"])
    assert result == "hi\n"
