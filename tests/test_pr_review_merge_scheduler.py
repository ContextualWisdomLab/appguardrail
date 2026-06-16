import os
import sys
import pytest
from unittest.mock import MagicMock

# Add scripts/ci to path so we can import the module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../scripts/ci')))
from pr_review_merge_scheduler import split_repo

def test_split_repo_valid():
    """Test happy path where repo splits correctly into owner and name."""
    assert split_repo("owner/name") == ("owner", "name")

def test_split_repo_invalid_format():
    """Test edge cases where splitting doesn't yield two parts without raising ValueError on split."""
    # split_repo("abc") would actually raise ValueError on split, but the code explicitly catches it.
    with pytest.raises(ValueError, match="repo must be owner/name, got 'abc'"):
        split_repo("abc")

def test_split_repo_missing_owner_or_name():
    """Test when split returns empty strings for owner or name."""
    with pytest.raises(ValueError, match="repo must be owner/name, got '/name'"):
        split_repo("/name")
    with pytest.raises(ValueError, match="repo must be owner/name, got 'owner/'"):
        split_repo("owner/")

def test_split_repo_mock_exception():
    """
    Test the error path where the split operation itself raises a ValueError.
    Rationale: Requires mocking the operation that throws the exception to hit this code path.
    """
    mock_repo = MagicMock()
    # Force the split method on the mock to raise a ValueError
    mock_repo.split.side_effect = ValueError("mocked split error")

    with pytest.raises(ValueError) as excinfo:
        split_repo(mock_repo)

    assert "repo must be owner/name" in str(excinfo.value)
