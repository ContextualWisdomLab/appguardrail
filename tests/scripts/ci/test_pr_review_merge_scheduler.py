import pytest
from scripts.ci.pr_review_merge_scheduler import is_opencode_context, split_repo

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


def test_is_opencode_context_checkrun_name():
    node = {
        "__typename": "CheckRun",
        "name": "opencode-review",
    }
    assert is_opencode_context(node) is True


@pytest.mark.parametrize("workflow_name", ["OpenCode Review", "OpenCode PR Review"])
def test_is_opencode_context_checkrun_workflow_name(workflow_name):
    node = {
        "__typename": "CheckRun",
        "name": "other-check",
        "checkSuite": {"workflowRun": {"workflow": {"name": workflow_name}}},
    }
    assert is_opencode_context(node) is True


def test_is_opencode_context_checkrun_false():
    node = {
        "__typename": "CheckRun",
        "name": "other-check",
        "checkSuite": {"workflowRun": {"workflow": {"name": "Other Workflow"}}},
    }
    assert is_opencode_context(node) is False


def test_is_opencode_context_checkrun_missing_fields():
    node = {
        "__typename": "CheckRun",
        "name": "other-check",
        "checkSuite": {},
    }
    assert is_opencode_context(node) is False

    node2 = {
        "__typename": "CheckRun",
        "name": "other-check",
        # missing checkSuite entirely
    }
    assert is_opencode_context(node2) is False


def test_is_opencode_context_statuscontext_match():
    node = {
        "__typename": "StatusContext",
        "context": "opencode-review",
    }
    assert is_opencode_context(node) is True


def test_is_opencode_context_statuscontext_mismatch():
    node = {
        "__typename": "StatusContext",
        "context": "other-review",
    }
    assert is_opencode_context(node) is False


def test_is_opencode_context_statuscontext_missing():
    node = {
        "__typename": "StatusContext",
        # missing context
    }
    assert is_opencode_context(node) is False


def test_is_opencode_context_missing_typename():
    node = {
        "context": "opencode-review",
    }
    assert is_opencode_context(node) is True
