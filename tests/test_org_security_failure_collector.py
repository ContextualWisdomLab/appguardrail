import importlib.util
import sys
from pathlib import Path

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
    monkeypatch.setattr(
        collector.urllib.request,
        "build_opener",
        lambda *_: FakeRedirectOpener("http://169.254.169.254/latest/meta-data"),
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
