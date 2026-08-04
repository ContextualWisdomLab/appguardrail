"""Coverage for the successful paginated drift-issue inventory path."""

from scripts.ci import collect_code_scanning_drift as drift


class PageResultClient:
    """Client returning one complete dedicated issue page."""

    def pages(self, path, params=None):
        """Return one ordinary issue through the production PageResult type."""
        assert path.endswith("/issues")
        assert params == {"state": "all", "labels": drift.DRIFT_LABEL}
        return drift.PageResult(
            "ok",
            (
                {
                    "number": 17,
                    "state": "open",
                    "title": "[code-scanning-drift] demo",
                    "body": "evidence",
                },
            ),
            True,
        )


def test_issue_index_accepts_complete_page_result() -> None:
    """The production client page wrapper must feed ordinary issue deduplication."""
    issues = drift._issue_items(
        PageResultClient(),
        "ContextualWisdomLab/appguardrail",
    )

    assert [issue["number"] for issue in issues] == [17]
