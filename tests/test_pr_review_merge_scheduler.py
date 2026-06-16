import pytest
from scripts.ci.pr_review_merge_scheduler import has_current_head_approval

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
    assert has_current_head_approval(pr) is True

def test_has_current_head_approval_true_from_review_decision():
    pr = {
        "headRefOid": "commit123",
        "reviewDecision": "APPROVED",
        "reviews": {
            "nodes": []
        }
    }
    assert has_current_head_approval(pr) is True

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
    assert has_current_head_approval(pr) is False

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
    assert has_current_head_approval(pr) is False

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
    assert has_current_head_approval(pr) is False

def test_has_current_head_approval_missing_keys():
    pr = {}
    assert has_current_head_approval(pr) is False
