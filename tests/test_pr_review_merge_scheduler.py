import runpy
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts" / "ci"))
import pr_review_merge_scheduler


def test_split_repo_success():
    assert pr_review_merge_scheduler.split_repo("owner/repo") == ("owner", "repo")


def test_split_repo_success_multiple_slashes():
    assert pr_review_merge_scheduler.split_repo("owner/repo/extra") == ("owner", "repo/extra")


def test_split_repo_invalid():
    with pytest.raises(ValueError, match="repo must be owner/name, got 'invalid'"):
        pr_review_merge_scheduler.split_repo("invalid")


def test_split_repo_empty_owner():
    with pytest.raises(ValueError, match="repo must be owner/name, got '/repo'"):
        pr_review_merge_scheduler.split_repo("/repo")


def test_split_repo_empty_repo():
    with pytest.raises(ValueError, match="repo must be owner/name, got 'owner/'"):
        pr_review_merge_scheduler.split_repo("owner/")


def test_error_path(capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["pr_review_merge_scheduler.py", "--repo", "owner/repo"])

    with patch("subprocess.run") as mock_run:
        mock_process = MagicMock()
        mock_process.returncode = 1
        mock_process.stderr = "fake error message"
        mock_run.return_value = mock_process

        with pytest.raises(SystemExit, match="1") as excinfo:
            runpy.run_path(
                str(Path(__file__).parent.parent / "scripts" / "ci" / "pr_review_merge_scheduler.py"),
                run_name="__main__",
            )

        assert excinfo.value.code == 1

    captured = capsys.readouterr()
    assert "Command failed" in captured.err
    assert "fake error message" in captured.err


def test_has_current_head_approval_true_from_review_state():
    pr = {
        "headRefOid": "commit123",
        "reviewDecision": "REVIEW_REQUIRED",
        "reviews": {
            "nodes": [
                {
                    "state": "APPROVED",
                    "author": {"login": "opencode-agent"},
                    "commit": {"oid": "commit123"},
                }
            ]
        }
    }
    assert pr_review_merge_scheduler.has_current_head_approval(pr) is True


def test_has_current_head_approval_true_from_review_decision():
    pr = {
        "headRefOid": "commit123",
        "reviewDecision": "APPROVED",
        "reviews": {
            "nodes": []
        }
    }
    assert pr_review_merge_scheduler.has_current_head_approval(pr) is True


def test_has_current_head_approval_false():
    pr = {
        "headRefOid": "commit123",
        "reviewDecision": "REVIEW_REQUIRED",
        "reviews": {
            "nodes": [
                {
                    "state": "CHANGES_REQUESTED",
                    "author": {"login": "opencode-agent"},
                    "commit": {"oid": "commit123"},
                }
            ]
        }
    }
    assert pr_review_merge_scheduler.has_current_head_approval(pr) is False


def test_has_current_head_approval_wrong_commit():
    pr = {
        "headRefOid": "commit123",
        "reviewDecision": "REVIEW_REQUIRED",
        "reviews": {
            "nodes": [
                {
                    "state": "APPROVED",
                    "author": {"login": "opencode-agent"},
                    "commit": {"oid": "oldcommit456"},
                }
            ]
        }
    }
    assert pr_review_merge_scheduler.has_current_head_approval(pr) is False


def test_has_current_head_approval_wrong_author():
    pr = {
        "headRefOid": "commit123",
        "reviewDecision": "REVIEW_REQUIRED",
        "reviews": {
            "nodes": [
                {
                    "state": "APPROVED",
                    "author": {"login": "some-other-user"},
                    "commit": {"oid": "commit123"},
                }
            ]
        }
    }
    assert pr_review_merge_scheduler.has_current_head_approval(pr) is False


def test_has_current_head_approval_missing_keys():
    pr = {}
    assert pr_review_merge_scheduler.has_current_head_approval(pr) is False


def test_has_current_head_changes_requested_ignores_retryable_agent_failure():
    pr = {
        "headRefOid": "commit123",
        "reviews": {
            "nodes": [
                {
                    "state": "CHANGES_REQUESTED",
                    "body": "OpenCode Agent review evidence was missing or invalid.\n\n- Reason: timeout",
                    "author": {"login": "opencode-agent[bot]"},
                    "commit": {"oid": "commit123"},
                }
            ]
        },
    }
    assert pr_review_merge_scheduler.has_current_head_changes_requested(pr) is False
    assert pr_review_merge_scheduler.has_retryable_current_head_failure(pr) is True


def test_inspect_pr_retries_after_retryable_agent_failure():
    pr = {
        "number": 7,
        "isDraft": False,
        "headRefOid": "commit123",
        "baseRefName": "develop",
        "baseRefOid": "base123",
        "headRefName": "feature/test",
        "headRepository": {"nameWithOwner": "owner/repo"},
        "reviewDecision": "REVIEW_REQUIRED",
        "reviewThreads": {"nodes": []},
        "reviews": {
            "nodes": [
                {
                    "state": "CHANGES_REQUESTED",
                    "body": "OpenCode Agent review evidence was missing or invalid.\n\n- Reason: timeout",
                    "author": {"login": "opencode-agent[bot]"},
                    "commit": {"oid": "commit123"},
                }
            ]
        },
        "statusCheckRollup": {"contexts": {"nodes": []}},
    }

    with patch.object(pr_review_merge_scheduler, "dispatch_opencode_review") as mock_dispatch:
        decision = pr_review_merge_scheduler.inspect_pr(
            "owner/repo",
            pr,
            dry_run=False,
            trigger_reviews=True,
            enable_auto_merge_flag=True,
            workflow="OpenCode Review",
        )

    mock_dispatch.assert_called_once_with("owner/repo", "OpenCode Review", pr, dry_run=False)
    assert decision == pr_review_merge_scheduler.Decision(
        7, "review_dispatch", "retrying OpenCode review after agent failure"
    )


def test_opencode_in_progress_empty_pr_context():
    assert pr_review_merge_scheduler.opencode_in_progress({}) is False

    pr = {"statusCheckRollup": {"contexts": {"nodes": []}}}
    assert pr_review_merge_scheduler.opencode_in_progress(pr) is False


def test_opencode_in_progress_requires_matching_context():
    pr = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": [
                    {"__typename": "CheckRun", "name": "lint", "status": "IN_PROGRESS"},
                    {"__typename": "StatusContext", "context": "ci/build", "state": "PENDING"},
                ]
            }
        }
    }
    assert pr_review_merge_scheduler.opencode_in_progress(pr) is False


def test_opencode_in_progress_ignores_terminal_states():
    pr = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": [
                    {"__typename": "CheckRun", "name": "opencode-review", "status": "COMPLETED"},
                    {"__typename": "CheckRun", "name": "opencode-review", "status": "SUCCESS"},
                    {"__typename": "StatusContext", "context": "opencode-review", "state": "FAILURE"},
                    {"__typename": "StatusContext", "context": "opencode-review", "state": "ERROR"},
                ]
            }
        }
    }
    assert pr_review_merge_scheduler.opencode_in_progress(pr) is False


def test_opencode_in_progress_detects_active_states():
    pr1 = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": [{"__typename": "CheckRun", "name": "opencode-review", "status": "IN_PROGRESS"}]
            }
        }
    }
    assert pr_review_merge_scheduler.opencode_in_progress(pr1) is True

    pr2 = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": [{"__typename": "StatusContext", "context": "opencode-review", "state": "PENDING"}]
            }
        }
    }
    assert pr_review_merge_scheduler.opencode_in_progress(pr2) is True

    pr3 = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": [{"__typename": "CheckRun", "name": "opencode-review"}]
            }
        }
    }
    assert pr_review_merge_scheduler.opencode_in_progress(pr3) is False


def test_opencode_in_progress_detects_workflow_name_and_mixed_contexts():
    pr = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": [
                    {
                        "__typename": "CheckRun",
                        "name": "review",
                        "status": "QUEUED",
                        "checkSuite": {"workflowRun": {"workflow": {"name": "OpenCode Review"}}},
                    }
                ]
            }
        }
    }
    assert pr_review_merge_scheduler.opencode_in_progress(pr) is True

    mixed_pr = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": [
                    {"__typename": "CheckRun", "name": "lint", "status": "IN_PROGRESS"},
                    {"__typename": "CheckRun", "name": "opencode-review", "status": "COMPLETED"},
                    {"__typename": "StatusContext", "context": "opencode-review", "state": "PENDING"},
                ]
            }
        }
    }
    assert pr_review_merge_scheduler.opencode_in_progress(mixed_pr) is True
