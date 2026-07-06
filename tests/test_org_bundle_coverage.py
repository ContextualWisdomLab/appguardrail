import pytest
from unittest.mock import patch, MagicMock
from appguardrail_core.org_bundle import (
    gh_repo_list, gh_pr_list, gh_error_message, write_bundle, OrgBundleError, bundle_manifest
)
from appguardrail_core.org_intelligence import OrgInventory, PullRequestGateSummary

@patch("shutil.which")
def test_gh_repo_list_empty(mock_which):
    mock_which.return_value = "/bin/gh"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = "[]"
        repos = gh_repo_list("testorg")
        assert repos == []

def test_gh_pr_list_no_repos():
    assert gh_pr_list("testorg", [], 10) == ([], [])

def test_gh_error_message():
    class DummyExc:
        stderr = "GraphQL error"
    assert "GraphQL error" in gh_error_message(DummyExc())

def test_write_bundle():
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmpdir:
        inv = OrgInventory(0, 0, 0, 0, 0, [], {}, {}, 0, False)
        prs = PullRequestGateSummary(0, {}, {}, {}, [])
        write_bundle(
            Path(tmpdir),
            report="report",
            evidence_payload={"foo": "bar", "overall_status": "READY"},
            inventory=inv,
            pr_summary=prs,
            generated_at="2024-01-01",
            owner="testorg",
            repos_source=None,
            prs_source=None
        )
        assert (Path(tmpdir) / "manifest.json").exists()
