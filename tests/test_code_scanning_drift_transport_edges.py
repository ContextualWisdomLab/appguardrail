"""Transport edge contracts for live Code Scanning drift collection."""

from scripts.ci.collect_code_scanning_drift import GitHub


def test_paginated_collection_classifies_malformed_json_as_unknown() -> None:
    """Invalid GitHub JSON must produce bounded unknown evidence, not an exception."""
    client = GitHub("read-token")

    class Response:
        headers = {"content-type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b"{not-json"

    class Opener:
        def open(self, request, timeout):
            assert request.full_url.startswith("https://api.github.com/")
            assert timeout == 30
            return Response()

    client.opener = Opener()

    result = client.pages("/repos/ContextualWisdomLab/demo/code-scanning/analyses")

    assert result.status == "malformed_payload"
    assert result.complete is False
    assert result.items == ()
