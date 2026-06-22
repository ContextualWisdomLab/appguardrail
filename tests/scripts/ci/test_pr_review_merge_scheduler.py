import pytest
import sys
import os
import json
from unittest.mock import patch, MagicMock

from scripts.ci.pr_review_merge_scheduler import (
    split_repo,
    run,
    gh_graphql,
    fetch_open_prs,
    context_nodes,
    is_opencode_context,
    opencode_in_progress,
    unresolved_thread_count,
    review_author_login,
    is_opencode_review,
    current_head_review_state,
    has_current_head_approval,
    has_current_head_changes_requested,
    enable_auto_merge,
    dispatch_opencode_review,
    inspect_pr,
    Decision,
    print_summary,
    self_test,
    parse_args,
    main
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

@patch('subprocess.run')
def test_run_success(mock_run):
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "output"
    mock_run.return_value = mock_result
    assert run(["echo"]) == "output"

@patch('subprocess.run')
def test_run_failure(mock_run):
    import subprocess
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = "err"
    mock_run.return_value = mock_result
    with pytest.raises(RuntimeError):
        run(["cmd"])

@patch('scripts.ci.pr_review_merge_scheduler.run')
def test_gh_graphql(mock_run):
    mock_run.return_value = '{"data": "value"}'
    res = gh_graphql("query", owner="foo", limit=10)
    assert res == {"data": "value"}
    mock_run.assert_called_once()
    call_args = mock_run.call_args[0][0]
    assert "gh" in call_args
    assert "-f" in call_args
    assert "-F" in call_args
    assert mock_run.call_args[1]["stdin"] == "query"

@patch('scripts.ci.pr_review_merge_scheduler.gh_graphql')
def test_fetch_open_prs(mock_graphql):
    mock_graphql.side_effect = [
        {
            "data": {
                "repository": {
                    "pullRequests": {
                        "nodes": [{"number": 1}],
                        "pageInfo": {"hasNextPage": True, "endCursor": "cursor1"}
                    }
                }
            }
        },
        {
            "data": {
                "repository": {
                    "pullRequests": {
                        "nodes": [{"number": 2}],
                        "pageInfo": {"hasNextPage": False, "endCursor": "cursor2"}
                    }
                }
            }
        }
    ]
    prs = fetch_open_prs("owner/repo", 100)
    assert len(prs) == 2
    assert prs[0]["number"] == 1
    assert prs[1]["number"] == 2

def test_context_nodes():
    assert context_nodes({}) == []
    pr = {"statusCheckRollup": {"contexts": {"nodes": [{"id": 1}]}}}
    assert context_nodes(pr) == [{"id": 1}]

def test_is_opencode_context():
    # CheckRun opencode-review
    assert is_opencode_context({"__typename": "CheckRun", "name": "opencode-review"})
    # CheckRun OpenCode Review
    assert is_opencode_context({"__typename": "CheckRun", "checkSuite": {"workflowRun": {"workflow": {"name": "OpenCode Review"}}}})
    # other context
    assert is_opencode_context({"context": "opencode-review"})
    assert not is_opencode_context({"context": "other"})

def test_opencode_in_progress():
    pr = {"statusCheckRollup": {"contexts": {"nodes": [{"__typename": "CheckRun", "name": "opencode-review", "status": "IN_PROGRESS"}]}}}
    assert opencode_in_progress(pr)

    pr2 = {"statusCheckRollup": {"contexts": {"nodes": [{"__typename": "CheckRun", "name": "opencode-review", "status": "SUCCESS"}]}}}
    assert not opencode_in_progress(pr2)

def test_unresolved_thread_count():
    assert unresolved_thread_count({}) == 0
    pr = {"reviewThreads": {"nodes": [{"isResolved": False, "isOutdated": False}, {"isResolved": True, "isOutdated": False}]}}
    assert unresolved_thread_count(pr) == 1

def test_is_opencode_review():
    assert is_opencode_review({"author": {"login": "opencode-agent-123"}})
    assert is_opencode_review({"author": {"login": "someone"}, "body": "OpenCode Agent here"})
    assert not is_opencode_review({"author": {"login": "user"}})

def test_current_head_review_state():
    pr = {
        "headRefOid": "abc",
        "reviews": {
            "nodes": [
                {"author": {"login": "opencode"}, "state": "APPROVED", "commit": {"oid": "abc"}},
                {"author": {"login": "user"}, "state": "CHANGES_REQUESTED", "commit": {"oid": "abc"}},
            ]
        }
    }
    assert current_head_review_state(pr, "APPROVED")
    assert not current_head_review_state(pr, "CHANGES_REQUESTED")

def test_enable_auto_merge():
    pr = {"number": 1, "headRefOid": "abc"}
    with patch('scripts.ci.pr_review_merge_scheduler.run') as mock_run:
        enable_auto_merge("repo", pr, dry_run=True)
        mock_run.assert_not_called()

        enable_auto_merge("repo", pr, dry_run=False)
        mock_run.assert_called_once_with(["gh", "pr", "merge", "1", "--repo", "repo", "--auto", "--merge", "--match-head-commit", "abc"])

def test_dispatch_opencode_review():
    pr = {"number": 1, "baseRefName": "main", "baseRefOid": "def", "headRefName": "feat", "headRefOid": "abc"}
    with patch('scripts.ci.pr_review_merge_scheduler.run') as mock_run:
        dispatch_opencode_review("repo", "workflow", pr, dry_run=True)
        mock_run.assert_not_called()

        dispatch_opencode_review("repo", "workflow", pr, dry_run=False)
        mock_run.assert_called_once()

def test_inspect_pr():
    pr_base = {"number": 1, "headRepository": {"nameWithOwner": "owner/repo"}, "baseRefName": "main"}
    # draft
    assert inspect_pr("owner/repo", {**pr_base, "isDraft": True}, dry_run=True, trigger_reviews=False, enable_auto_merge_flag=False, workflow="w", base_branch="main").action == "skip"
    # wrong base
    assert inspect_pr("owner/repo", {**pr_base, "baseRefName": "other"}, dry_run=True, trigger_reviews=False, enable_auto_merge_flag=False, workflow="w", base_branch="main").action == "skip"
    # wrong repo
    assert inspect_pr("owner/repo", {**pr_base, "headRepository": {"nameWithOwner": "other/repo"}}, dry_run=True, trigger_reviews=False, enable_auto_merge_flag=False, workflow="w", base_branch="main").action == "skip"

    # unresolved threads
    pr = {**pr_base, "reviewThreads": {"nodes": [{"isResolved": False, "isOutdated": False}]}}
    assert inspect_pr("owner/repo", pr, dry_run=True, trigger_reviews=False, enable_auto_merge_flag=False, workflow="w", base_branch="main").action == "block"

def test_inspect_pr_approval():
    pr_base = {"number": 1, "headRepository": {"nameWithOwner": "owner/repo"}, "baseRefName": "main", "headRefOid": "abc"}
    # changes requested
    pr = {**pr_base, "reviews": {"nodes": [{"author": {"login": "opencode"}, "state": "CHANGES_REQUESTED", "commit": {"oid": "abc"}}]}}
    assert inspect_pr("owner/repo", pr, dry_run=True, trigger_reviews=False, enable_auto_merge_flag=False, workflow="w", base_branch="main").action == "block"

    # approved, auto merge already on
    pr = {**pr_base, "reviews": {"nodes": [{"author": {"login": "opencode"}, "state": "APPROVED", "commit": {"oid": "abc"}}]}, "autoMergeRequest": {}}
    assert inspect_pr("owner/repo", pr, dry_run=True, trigger_reviews=False, enable_auto_merge_flag=False, workflow="w", base_branch="main").action == "wait"

    # approved, auto merge disabled by flag
    pr = {**pr_base, "reviews": {"nodes": [{"author": {"login": "opencode"}, "state": "APPROVED", "commit": {"oid": "abc"}}]}}
    assert inspect_pr("owner/repo", pr, dry_run=True, trigger_reviews=False, enable_auto_merge_flag=False, workflow="w", base_branch="main").action == "wait"

    # approved, auto merge enabled
    pr = {**pr_base, "reviews": {"nodes": [{"author": {"login": "opencode"}, "state": "APPROVED", "commit": {"oid": "abc"}}]}}
    with patch('scripts.ci.pr_review_merge_scheduler.enable_auto_merge') as mock_merge:
        assert inspect_pr("owner/repo", pr, dry_run=True, trigger_reviews=False, enable_auto_merge_flag=True, workflow="w", base_branch="main").action == "auto_merge"
        mock_merge.assert_called_once()

    # in progress
    pr = {**pr_base, "statusCheckRollup": {"contexts": {"nodes": [{"__typename": "CheckRun", "name": "opencode-review", "status": "IN_PROGRESS"}]}}}
    assert inspect_pr("owner/repo", pr, dry_run=True, trigger_reviews=False, enable_auto_merge_flag=False, workflow="w", base_branch="main").action == "wait"

    # trigger review
    with patch('scripts.ci.pr_review_merge_scheduler.dispatch_opencode_review') as mock_dispatch:
        assert inspect_pr("owner/repo", pr_base, dry_run=True, trigger_reviews=True, enable_auto_merge_flag=False, workflow="w", base_branch="main").action == "review_dispatch"
        mock_dispatch.assert_called_once()

    # block if no trigger
    assert inspect_pr("owner/repo", pr_base, dry_run=True, trigger_reviews=False, enable_auto_merge_flag=False, workflow="w", base_branch="main").action == "block"


def test_print_summary(capsys):
    print_summary([Decision(1, "wait", "reason")], dry_run=True, base_branch="main", project_flow="flow")
    out = capsys.readouterr().out
    assert "PR #1: wait: reason" in out
    assert '"inspected": 1' in out

def test_self_test():
    self_test()

@patch("scripts.ci.pr_review_merge_scheduler.os.environ.get")
def test_parse_args(mock_env_get):
    mock_env_get.return_value = "val"
    args = parse_args(["--repo", "r", "--base-branch", "b", "--project-flow", "f"])
    assert args.repo == "r"
    assert args.base_branch == "b"
    assert args.project_flow == "f"

def test_main_missing_args():
    with patch('scripts.ci.pr_review_merge_scheduler.parse_args') as mock_parse:
        mock_parse.return_value = MagicMock(self_test=False, repo="", base_branch="", project_flow="")
        with pytest.raises(SystemExit, match="--repo is required"):
            main([])

        mock_parse.return_value = MagicMock(self_test=False, repo="r", base_branch="", project_flow="")
        with pytest.raises(SystemExit, match="--base-branch is required"):
            main([])

        mock_parse.return_value = MagicMock(self_test=False, repo="r", base_branch="b", project_flow="")
        with pytest.raises(SystemExit, match="--project-flow is required"):
            main([])

@patch("scripts.ci.pr_review_merge_scheduler.fetch_open_prs")
def test_main_success(mock_fetch):
    mock_fetch.return_value = [{"number": 1, "headRepository": {"nameWithOwner": "owner/repo"}, "baseRefName": "main"}]
    with patch('scripts.ci.pr_review_merge_scheduler.parse_args') as mock_parse:
        mock_parse.return_value = MagicMock(self_test=False, repo="owner/repo", base_branch="main", project_flow="f", dry_run=True, trigger_reviews=False, enable_auto_merge=False, review_workflow="w", max_prs=100)
        assert main([]) == 0

def test_main_self_test():
    with patch('scripts.ci.pr_review_merge_scheduler.self_test') as mock_self_test:
        with patch('scripts.ci.pr_review_merge_scheduler.parse_args') as mock_parse:
            mock_parse.return_value = MagicMock(self_test=True)
            assert main([]) == 0
            mock_self_test.assert_called_once()

def test_opencode_in_progress_missing_status():
    pr = {"statusCheckRollup": {"contexts": {"nodes": [{"__typename": "CheckRun", "name": "opencode-review"}]}}}
    assert opencode_in_progress(pr) is False

def test_inspect_pr_auto_merge_disabled():
    pr_base = {"number": 1, "headRepository": {"nameWithOwner": "owner/repo"}, "baseRefName": "main", "headRefOid": "abc"}
    pr = {**pr_base, "reviews": {"nodes": [{"author": {"login": "opencode"}, "state": "APPROVED", "commit": {"oid": "abc"}}]}}
    assert inspect_pr("owner/repo", pr, dry_run=True, trigger_reviews=False, enable_auto_merge_flag=False, workflow="w", base_branch="main").action == "wait"

def test_opencode_in_progress_true():
    pr = {"statusCheckRollup": {"contexts": {"nodes": [{"__typename": "CheckRun", "name": "opencode-review", "status": "QUEUED"}]}}}
    assert opencode_in_progress(pr) is True

def test_opencode_in_progress_skip_other_context():
    pr = {"statusCheckRollup": {"contexts": {"nodes": [{"context": "other", "status": "QUEUED"}, {"context": "opencode-review", "status": "COMPLETED"}]}}}
    assert opencode_in_progress(pr) is False

def test_inspect_pr_auto_merge_disabled_with_flag():
    pr_base = {"number": 1, "headRepository": {"nameWithOwner": "owner/repo"}, "baseRefName": "main", "headRefOid": "abc"}
    pr = {**pr_base, "reviews": {"nodes": [{"author": {"login": "opencode"}, "state": "APPROVED", "commit": {"oid": "abc"}}]}}
    assert inspect_pr("owner/repo", pr, dry_run=True, trigger_reviews=False, enable_auto_merge_flag=False, workflow="w", base_branch="main").action == "wait"

def test_inspect_pr_auto_merge_already_enabled():
    pr_base = {"number": 1, "headRepository": {"nameWithOwner": "owner/repo"}, "baseRefName": "main", "headRefOid": "abc"}
    pr = {**pr_base, "reviews": {"nodes": [{"author": {"login": "opencode"}, "state": "APPROVED", "commit": {"oid": "abc"}}]}, "autoMergeRequest": {"enabledBy": "someone"}}
    assert inspect_pr("owner/repo", pr, dry_run=True, trigger_reviews=False, enable_auto_merge_flag=True, workflow="w", base_branch="main").action == "wait"
