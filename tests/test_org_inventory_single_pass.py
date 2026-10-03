
from appguardrail_core.org_intelligence import build_org_inventory


def test_build_org_inventory_has_one_repository_traversal_after_materialization():
    """Keep inventory aggregation in the single loop this optimization promises."""
    class TraversalTrackingIterable:
        def __init__(self, data):
            self.data = data
            self.traversals = 0

        def __iter__(self):
            self.traversals += 1
            return iter(self.data)

    mock_repos = [
        {"name": "repo1", "isFork": False, "isPrivate": True, "defaultBranchRef": {"name": "main"}, "primaryLanguage": {"name": "Python"}},
        {"name": "repo2", "isFork": True, "isPrivate": False, "defaultBranchRef": {"name": "main"}, "primaryLanguage": {"name": "Go"}}
    ]
    tracker = TraversalTrackingIterable(mock_repos)
    build_org_inventory(tracker)

    assert tracker.traversals == 1
