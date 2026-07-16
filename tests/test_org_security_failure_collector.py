import importlib.util
import io
import sys
from pathlib import Path

import pytest

from appguardrail_core import issueops

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "ci"
    / "collect_org_security_failures.py"
)
SPEC = importlib.util.spec_from_file_location(
    "collect_org_security_failures", MODULE_PATH
)
collector = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = collector
assert SPEC.loader is not None
SPEC.loader.exec_module(collector)


def finding(**overrides):
    base = {
        "repo": "ContextualWisdomLab/naruon",
        "workflow": "Strix Security Scan",
        "run_id": 28492006630,
        "run_url": "https://github.com/ContextualWisdomLab/naruon/actions/runs/28492006630",
        "job_id": 84450511793,
        "job_name": "strix",
        "job_url": "https://github.com/ContextualWisdomLab/naruon/actions/runs/28492006630/job/84450511793",
        "conclusion": "failure",
        "branch": "develop",
        "head_sha": "abc123",
        "event": "pull_request",
        "pr_numbers": [265],
        "snippet": "VULN-0001 CRITICAL example",
    }
    base.update(overrides)
    return base


def test_matching_conclusions_and_run_url_pattern():
    assert collector.is_security_name("Strix")
    assert collector.is_failure("failure")
    assert collector.parse_run_url(
        "https://github.com/ContextualWisdomLab/naruon/actions/runs/28492006630/job/84450511793#step:21:1"
    ) == ("ContextualWisdomLab/naruon", 28492006630)


class FakeClient:
    def __init__(self, issues=None):
        self.issues = issues or []
        self.calls = []

    def pages(self, path, params=None):
        self.calls.append(("pages", path, params))
        return self.issues if path.endswith("/issues") else []

    def request(self, method, path, data=None):
        self.calls.append(("request", method, path, data))
        return {
            "number": 99,
            "state": "open",
            "title": data.get("title", ""),
            "body": data.get("body", ""),
        }


class FakeRedirectResponse:
    def __init__(self, location):
        self.location = location

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def geturl(self):
        return self.location

    def read(self):
        return self.location.encode()


class FakeRedirectOpener:
    def __init__(self, location):
        self.location = location

    def open(self, request, timeout):
        return FakeRedirectResponse(self.location)


def test_job_log_rejects_dangerous_redirect_scheme(monkeypatch):
    client = collector.GitHub("token")
    monkeypatch.setattr(
        collector.urllib.request,
        "build_opener",
        lambda *_: FakeRedirectOpener("file:///etc/passwd"),
    )

    assert "Invalid or dangerous URL scheme" in client.job_log(
        "ContextualWisdomLab/naruon", 123
    )


def test_job_log_rejects_internal_redirect_host(monkeypatch):
    client = collector.GitHub("token")

    blocked_urls = [
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://10.0.0.5/",
        "http://2130706433/",
        "http://0177.0.0.1/",
        "http://0x7f.0.0.1/",
    ]

    for url in blocked_urls:
        monkeypatch.setattr(
            collector.urllib.request,
            "build_opener",
            lambda *_, u=url: FakeRedirectOpener(u),
        )
        assert "Access to internal address blocked" in client.job_log(
            "ContextualWisdomLab/naruon", 123
        )


def test_publish_skips_duplicate_and_reopens_closed_issue():
    item = finding()
    issue = {
        "number": 17,
        "state": "open",
        "title": collector.title(item),
        "body": issueops.marker(
            item["repo"], item["workflow"], {collector.seen_key(item)}
        ),
    }
    client = FakeClient([issue])
    collector.publish_one(
        client,
        "ContextualWisdomLab/appguardrail",
        item,
        True,
        {issue["title"]: issue},
        set(),
    )
    assert all(call[0] != "request" for call in client.calls)

    unseen = finding(job_id=999, snippet="::error:: security failure")
    closed = dict(
        issue,
        state="closed",
        body=issueops.marker(item["repo"], item["workflow"], {"1:2"}),
    )
    client = FakeClient([closed])
    collector.publish_one(
        client,
        "ContextualWisdomLab/appguardrail",
        unseen,
        False,
        {closed["title"]: closed},
        set(),
    )
    patch = [
        call
        for call in client.calls
        if call[:3]
        == ("request", "PATCH", "/repos/ContextualWisdomLab/appguardrail/issues/17")
    ]
    comment = [
        call
        for call in client.calls
        if call[:3]
        == (
            "request",
            "POST",
            "/repos/ContextualWisdomLab/appguardrail/issues/17/comments",
        )
    ]
    assert patch and patch[0][3]["state"] == "open"
    assert collector.seen_key(unseen) in patch[0][3]["body"]
    assert comment


def test_publish_findings_fetches_issues_once_and_caches_labels(capsys):
    client = FakeClient([])
    collector.publish_findings(
        client,
        "ContextualWisdomLab/appguardrail",
        [finding(run_id=1, job_id=10), finding(run_id=2, job_id=20)],
        dry_run=True,
    )
    output = capsys.readouterr().out
    assert (
        client.calls.count(
            (
                "pages",
                "/repos/ContextualWisdomLab/appguardrail/issues",
                {"state": "all", "labels": collector.ISSUE_LABEL},
            )
        )
        == 1
    )
    assert output.count("DRY_RUN label ContextualWisdomLab/appguardrail") == 3
    assert "DRY_RUN create issue" in output
    assert "DRY_RUN update issue #dry-run" in output


def test_collector_terminal_output_escapes_ansi_osc_and_bell(capsys):
    malicious = finding(
        workflow="strix\x1b[2J\x1b]0;owned\x07",
        snippet="payload\x1b]52;c;ZXhmaWw=\x07",
    )
    collector.publish_one(
        FakeClient([]),
        "ContextualWisdomLab/appguardrail",
        malicious,
        True,
        {},
        set(),
    )
    output = capsys.readouterr().out
    assert "\x1b" not in output
    assert "\x07" not in output
    assert "\\x1b[2J" in output
    assert "\\x07" in output


@pytest.mark.parametrize(
    "api",
    [
        "file:///etc/passwd",
        "http://api.github.com",
        "https://attacker.example",
        "https://api.github.com.attacker.example",
        "https://token@api.github.com",
        "https://api.github.com:444",
        "https://api.github.com/repos",
    ],
)
def test_github_init_rejects_untrusted_api_roots(api):
    with pytest.raises(
        ValueError, match="GitHub API URL must be exactly https://api.github.com"
    ):
        collector.GitHub("token", api)


def test_github_api_request_does_not_follow_token_bearing_redirect(monkeypatch):
    opened = []

    class _Opener:
        def open(self, request, timeout):
            opened.append(
                (request.full_url, request.headers.get("Authorization"), timeout)
            )
            raise collector.urllib.error.HTTPError(
                request.full_url,
                302,
                "Found",
                {"location": "https://attacker.example/steal"},
                io.BytesIO(b"redirect blocked"),
            )

    def _build(handler):
        assert handler is collector.NoRedirect
        return _Opener()

    monkeypatch.setattr(collector.urllib.request, "build_opener", _build)
    client = collector.GitHub("super-secret-token")
    with pytest.raises(RuntimeError, match="302 redirect blocked"):
        client.request("GET", "/user")
    assert opened == [("https://api.github.com/user", "Bearer super-secret-token", 30)]


def test_job_log_rejects_internal_dns_resolution(monkeypatch):
    client = collector.GitHub("token")
    monkeypatch.setattr(
        collector.urllib.request,
        "build_opener",
        lambda *_: FakeRedirectOpener(
            "https://productionresultssa14.blob.core.windows.net/job-logs.txt"
        ),
    )
    monkeypatch.setattr(collector, "resolve_public_url", lambda *_args, **_kwargs: None)

    assert "Access to internal address blocked" in client.job_log(
        "ContextualWisdomLab/naruon", 123
    )


def test_job_log_rejects_unexpected_redirect_host(monkeypatch):
    client = collector.GitHub("token")
    monkeypatch.setattr(
        collector.urllib.request,
        "build_opener",
        lambda *_: FakeRedirectOpener("https://attacker.example/job-logs.txt"),
    )

    assert "Unexpected log download host blocked" in client.job_log(
        "ContextualWisdomLab/naruon", 123
    )


def test_job_log_allows_public_github_log_host(monkeypatch):
    client = collector.GitHub("token")
    monkeypatch.setattr(
        collector.urllib.request,
        "build_opener",
        lambda *_: FakeRedirectOpener(
            "https://productionresultssa14.blob.core.windows.net/job-logs.txt"
        ),
    )
    parsed = collector.urllib.parse.urlparse(
        "https://productionresultssa14.blob.core.windows.net/job-logs.txt"
    )
    target = (parsed, "93.184.216.34", 443)
    monkeypatch.setattr(
        collector, "resolve_public_url", lambda *_args, **_kwargs: target
    )
    seen = []

    def request_pinned(resolved, **kwargs):
        seen.append((resolved, kwargs))
        return 200, {}, b"job log contents"

    monkeypatch.setattr(collector, "request_pinned_url", request_pinned)

    assert client.job_log("ContextualWisdomLab/naruon", 123) == "job log contents"
    assert seen[0][0] == target


def test_job_log_download_uses_validated_ip_without_second_resolution(monkeypatch):
    location = "https://productionresultssa14.blob.core.windows.net/job-logs.txt"
    monkeypatch.setattr(
        collector.urllib.request,
        "build_opener",
        lambda *_: FakeRedirectOpener(location),
    )
    parsed = collector.urllib.parse.urlparse(location)
    resolutions = []

    def resolve(url, **_kwargs):
        resolutions.append(url)
        return parsed, "93.184.216.34", 443

    def request(target, **_kwargs):
        assert target[1] == "93.184.216.34"
        return 200, {}, b"pinned"

    monkeypatch.setattr(collector, "resolve_public_url", resolve)
    monkeypatch.setattr(collector, "request_pinned_url", request)
    assert collector.GitHub("token").job_log("owner/repo", 123) == "pinned"
    assert resolutions == [location]
