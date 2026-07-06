import pytest
from unittest.mock import patch, MagicMock
from scripts.ci.collect_org_security_failures import parse_args, main, GitHub

def test_parse_args():
    args = parse_args(["--owner", "test"])
    assert args.owner == "test"

@patch("scripts.ci.collect_org_security_failures.GitHub.request")
@patch("scripts.ci.collect_org_security_failures.GitHub.pages")
def test_main_empty(mock_pages, mock_request):
    mock_pages.return_value = []
    with patch("sys.argv", ["script", "--owner", "test"]):
        import os
        orig_getenv = os.getenv
        def mock_getenv(k, d=None):
            if k == "GH_TOKEN": return "token"
            return orig_getenv(k, d)
        with patch("os.getenv", side_effect=mock_getenv):
            assert main() == 0

def test_github_request():
    gh = GitHub("token", "http://test.com")
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = b'{"data": "test"}'
        mock_resp.getheader.return_value = "application/json"
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        result = gh.request("GET", "/test")
        assert result == {"data": "test"} or result == '{"data": "test"}'

def test_github_pages():
    gh = GitHub("token", "http://test.com")
    with patch.object(gh, "request") as mock_request:
        mock_request.side_effect = [[1, 2], []]
        res = gh.pages("/test")
        assert res == [1, 2]

def test_job_log():
    gh = GitHub("token", "http://test.com")
    with patch("scripts.ci.collect_org_security_failures.urllib.request.build_opener") as mock_opener:
        mock_open = MagicMock()
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = b'log data'
        mock_resp.geturl.return_value = 'http://test.com/log'
        mock_open.open.return_value.__enter__.return_value = mock_resp
        mock_opener.return_value = mock_open

        result = gh.job_log("repo", 1)
        assert result == "log data"
