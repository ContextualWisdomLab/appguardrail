import argparse

import pytest
from scripts.ci.pr_review_merge_scheduler import positive_int, split_repo

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


def test_positive_int_accepts_positive_values():
    assert positive_int("1") == 1
    assert positive_int("100") == 100


@pytest.mark.parametrize("value", ["0", "-1", "abc"])
def test_positive_int_rejects_invalid_values(value):
    with pytest.raises(argparse.ArgumentTypeError, match="must be a positive integer"):
        positive_int(value)
