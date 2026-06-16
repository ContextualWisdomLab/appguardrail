from scripts.ci.pr_review_merge_scheduler import opencode_in_progress

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
