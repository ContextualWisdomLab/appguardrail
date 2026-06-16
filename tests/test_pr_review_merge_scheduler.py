import sys
from pathlib import Path

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


def test_empty_pr_context():
    assert pr_review_merge_scheduler.opencode_in_progress({}) is False

    pr = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": []
            }
        }
    }
    assert pr_review_merge_scheduler.opencode_in_progress(pr) is False


def test_no_opencode_context():
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


def test_opencode_completed_status():
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
    assert pr_review_merge_scheduler.opencode_in_progress(pr1) is True

    pr2 = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": [
                    {"__typename": "StatusContext", "context": "opencode-review", "state": "PENDING"}
                ]
            }
        }
    }
    assert pr_review_merge_scheduler.opencode_in_progress(pr2) is True

    pr3 = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": [
                    {"__typename": "CheckRun", "name": "opencode-review"}
                ]
            }
        }
    }
    assert pr_review_merge_scheduler.opencode_in_progress(pr3) is False


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
                        },
                    }
                ]
            }
        }
    }
    assert pr_review_merge_scheduler.opencode_in_progress(pr) is True


def test_multiple_contexts_one_in_progress():
    pr = {
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
    assert pr_review_merge_scheduler.opencode_in_progress(pr) is True
