from scripts.ci.pr_review_merge_scheduler import is_opencode_context, opencode_in_progress

def test_empty_pr_context():
    # Empty PR dict
    assert opencode_in_progress({}) is False

    # PR with no context nodes
    pr = {
        "statusCheckRollup": {
            "contexts": {
                "nodes": []
            }
        }
    }
    assert opencode_in_progress(pr) is False

def test_no_opencode_context():
    # PR with irrelevant context nodes
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


def test_is_opencode_context_checkrun_name():
    node = {
        "__typename": "CheckRun",
        "name": "opencode-review",
    }
    assert is_opencode_context(node) is True


def test_is_opencode_context_checkrun_workflow_name():
    node = {
        "__typename": "CheckRun",
        "name": "other-check",
        "checkSuite": {
            "workflowRun": {
                "workflow": {
                    "name": "OpenCode Review"
                }
            }
        }
    }
    assert is_opencode_context(node) is True


def test_is_opencode_context_checkrun_false():
    node = {
        "__typename": "CheckRun",
        "name": "other-check",
        "checkSuite": {
            "workflowRun": {
                "workflow": {
                    "name": "Other Workflow"
                }
            }
        }
    }
    assert is_opencode_context(node) is False


def test_is_opencode_context_checkrun_missing_fields():
    node = {
        "__typename": "CheckRun",
        "name": "other-check",
        "checkSuite": {}
    }
    assert is_opencode_context(node) is False

    node2 = {
        "__typename": "CheckRun",
        "name": "other-check",
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
    }
    assert is_opencode_context(node) is False


def test_is_opencode_context_missing_typename():
    node = {
        "context": "opencode-review",
    }
    assert is_opencode_context(node) is True
