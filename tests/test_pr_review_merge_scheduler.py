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
