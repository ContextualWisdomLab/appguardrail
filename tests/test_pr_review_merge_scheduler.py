import runpy
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.ci import pr_review_merge_scheduler
from scripts.ci.pr_review_merge_scheduler import opencode_in_progress


def test_empty_pr_context():
    assert opencode_in_progress({}) is False

    pr = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": []
            }
        }
    }
    assert opencode_in_progress(pr) is False


def test_no_opencode_context():
    pr = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": [
                    {"__typename": "CheckRun", "name": "lint", "status": "IN_PROGRESS"},
                    {"__typename": "StatusContext", "context": "ci/build", "state": "PENDING"}
                ]
            }
        }
    }
    assert opencode_in_progress(pr) is False


def test_opencode_completed_status():
    pr = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": [
                    {"__typename": "CheckRun", "name": "opencode-review", "status": "COMPLETED"},
                    {"__typename": "CheckRun", "name": "opencode-review", "status": "SUCCESS"},
                    {"__typename": "StatusContext", "context": "opencode-review", "state": "FAILURE"},
                    {"__typename": "StatusContext", "context": "opencode-review", "state": "ERROR"}
                ]
            }
        }
    }
    assert opencode_in_progress(pr) is False


def test_opencode_in_progress_status():
    pr1 = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": [
                    {"__typename": "CheckRun", "name": "opencode-review", "status": "IN_PROGRESS"}
                ]
            }
        }
    }
    assert opencode_in_progress(pr1) is True

    pr2 = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": [
                    {"__typename": "StatusContext", "context": "opencode-review", "state": "PENDING"}
                ]
            }
        }
    }
    assert opencode_in_progress(pr2) is True

    pr3 = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": [
                    {"__typename": "CheckRun", "name": "opencode-review"}
                ]
            }
        }
    }
    assert opencode_in_progress(pr3) is False


def test_opencode_workflow_name_in_progress():
    pr = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": [
                    {
                        "__typename": "CheckRun",
                        "name": "review",
                        "status": "QUEUED",
                        "checkSuite": {
                            "workflowRun": {
                                "workflow": {
                                    "name": "OpenCode Review"
                                }
                            }
                        }
                    }
                ]
            }
        }
    }
    assert opencode_in_progress(pr) is True


def test_multiple_contexts_one_in_progress():
    pr = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": [
                    {"__typename": "CheckRun", "name": "lint", "status": "IN_PROGRESS"},
                    {"__typename": "CheckRun", "name": "opencode-review", "status": "COMPLETED"},
                    {"__typename": "StatusContext", "context": "opencode-review", "state": "PENDING"}
                ]
            }
        }
    }
    assert opencode_in_progress(pr) is True


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


def test_split_repo_both_parts_empty():
    with pytest.raises(ValueError, match="repo must be owner/name, got '/'"):
        pr_review_merge_scheduler.split_repo("/")


def test_split_repo_wraps_split_value_error():
    repo = MagicMock()
    repo.split.side_effect = ValueError("mocked split error")

    with pytest.raises(ValueError, match=r"repo must be owner/name, got <MagicMock"):
        pr_review_merge_scheduler.split_repo(repo)


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
    assert pr_review_merge_scheduler.has_current_head_approval({}) is False
