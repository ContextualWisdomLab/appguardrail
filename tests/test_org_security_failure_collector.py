import importlib.util
import sys
from pathlib import Path

from appguardrail_core import issueops


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "ci" / "collect_org_security_failures.py"
SPEC = importlib.util.spec_from_file_location("collect_org_security_failures", MODULE_PATH)
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
        return {"number": 99, "state": "open", "title": data.get("title", ""), "body": data.get("body", "")}


class FakeApiClient:
    """Fake HTTP-shaped GitHub client for exercising collect()."""

    def __init__(self, *, repos, runs, jobs, logs=None):
        self.repos = repos
        self.runs = runs
        self.jobs = jobs
        self.logs = logs or {}

    def pages(self, path, params=None):
        if path == "/installation/repositories":
            return self.repos
        if path.endswith("/actions/runs"):
            repo = path[len("/repos/"):-len("/actions/runs")]
            return self.runs.get(repo, [])
        if path.endswith("/jobs"):
            return self.jobs.get(path, [])
        return []

    def request(self, method, path, data=None, params=None):
        return None

    def job_log(self, repo, job_id):
        return self.logs.get(job_id, "::error:: generic failure")


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
        "body": issueops.marker(item["repo"], item["workflow"], {collector.seen_key(item)}),
    }
    client = FakeClient([issue])
    collector.publish_one(client, "ContextualWisdomLab/appguardrail", item, True, {issue["title"]: issue}, set())
    assert all(call[0] != "request" for call in client.calls)

    unseen = finding(job_id=999, snippet="::error:: security failure")
    closed = dict(issue, state="closed", body=issueops.marker(item["repo"], item["workflow"], {"1:2"}))
    client = FakeClient([closed])
    collector.publish_one(client, "ContextualWisdomLab/appguardrail", unseen, False, {closed["title"]: closed}, set())
    patch = [call for call in client.calls if call[:3] == ("request", "PATCH", "/repos/ContextualWisdomLab/appguardrail/issues/17")]
    comment = [call for call in client.calls if call[:3] == ("request", "POST", "/repos/ContextualWisdomLab/appguardrail/issues/17/comments")]
    assert patch and patch[0][3]["state"] == "open"
    assert collector.seen_key(unseen) in patch[0][3]["body"]
    assert comment


def test_publish_findings_fetches_issues_once_and_caches_labels(capsys):
    client = FakeClient([])
    collector.publish_findings(
        client,
        "ContextualWisdomLab/appguardrail",
        # Same repo:workflow (one issue) but two distinct failure signatures, so
        # the first creates and the second appends an update rather than deduping.
        [
            finding(run_id=1, job_id=10, snippet="::error:: RateLimitError"),
            finding(run_id=2, job_id=20, snippet="::error:: Trivy CRITICAL CVE"),
        ],
        dry_run=True,
    )
    output = capsys.readouterr().out
    assert client.calls.count(("pages", "/repos/ContextualWisdomLab/appguardrail/issues", {"state": "all", "labels": collector.ISSUE_LABEL})) == 1
    assert output.count("DRY_RUN label ContextualWisdomLab/appguardrail") == 4
    assert "DRY_RUN create issue" in output
    assert "DRY_RUN update issue #dry-run" in output


def test_ci_failure_label_distinguishes_from_strix_finding_issues():
    # These general CI/security-failure issues carry a `ci-failure` label; the
    # sibling source-side Strix emitter uses `strix`/`security`. No overlap.
    assert collector.CI_FAILURE_LABEL == "ci-failure"
    assert "strix" not in {collector.ISSUE_LABEL, collector.SECURITY_LABEL, collector.CI_FAILURE_LABEL}


def _run(**overrides):
    run_id = overrides.get("id", 100)
    base = {
        "id": run_id,
        "name": "Strix Security Scan",
        "conclusion": "failure",
        "html_url": f"https://github.com/ContextualWisdomLab/naruon/actions/runs/{run_id}",
        "head_sha": "abc123",
        "head_branch": "develop",
        "event": "pull_request",
        "updated_at": "2026-07-08T10:00:00Z",
        "created_at": "2026-07-08T10:00:00Z",
        "pull_requests": [],
    }
    base.update(overrides)
    return base


def _args(**overrides):
    return collector.parse_args(
        [
            "--owner",
            overrides.get("owner", "ContextualWisdomLab"),
            "--target-repo",
            overrides.get("target_repo", "ContextualWisdomLab/appguardrail"),
            "--lookback-hours",
            "100000",
        ]
    )


def test_collect_returns_findings_and_resolutions():
    repo = "ContextualWisdomLab/naruon"
    failing = _run(id=100, conclusion="failure", updated_at="2026-07-08T09:00:00Z")
    passing = _run(id=101, conclusion="success", updated_at="2026-07-08T11:00:00Z")
    unrelated = _run(id=102, name="Unit Tests", conclusion="failure", updated_at="2026-07-08T09:30:00Z")
    client = FakeApiClient(
        repos=[{"full_name": repo}],
        runs={repo: [failing, passing, unrelated]},
        jobs={
            f"/repos/{repo}/actions/runs/100/jobs": [
                {"id": 900, "name": "strix", "conclusion": "failure", "workflow_name": "Strix Security Scan", "html_url": ""}
            ],
            f"/repos/{repo}/actions/runs/102/jobs": [
                {"id": 902, "name": "pytest", "conclusion": "failure", "workflow_name": "Unit Tests", "html_url": ""}
            ],
        },
    )
    findings, resolutions = collector.collect(client, _args())
    # Only the security-named failing job is a finding; the unit-test failure is ignored.
    assert len(findings) == 1
    assert findings[0]["workflow"] == "Strix Security Scan"
    # The later successful Strix run marks that workflow resolved (close-on-fix input).
    assert (repo, "Strix Security Scan") in resolutions
    assert resolutions[(repo, "Strix Security Scan")]["run_url"].endswith("/runs/101")


def test_close_resolved_closes_open_issue_with_comment():
    repo = "ContextualWisdomLab/naruon"
    item = finding(repo=repo, workflow="Strix Security Scan")
    issue = {
        "number": 42,
        "state": "open",
        "title": collector.title(item),
        "body": issueops.marker(repo, "Strix Security Scan", {collector.seen_key(item)}),
    }
    resolutions = {(repo, "Strix Security Scan"): {"repo": repo, "workflow": "Strix Security Scan", "run_url": "https://x/runs/2", "head_sha": "def"}}

    # Real close: comment then PATCH state=closed.
    client = FakeClient([issue])
    collector.close_resolved(client, "ContextualWisdomLab/appguardrail", resolutions, False, {issue["title"]: issue})
    comment = [c for c in client.calls if c[:3] == ("request", "POST", "/repos/ContextualWisdomLab/appguardrail/issues/42/comments")]
    patch = [c for c in client.calls if c[:3] == ("request", "PATCH", "/repos/ContextualWisdomLab/appguardrail/issues/42")]
    assert comment and patch and patch[0][3]["state"] == "closed"

    # Already-closed issues are left alone.
    closed_issue = dict(issue, state="closed")
    client = FakeClient([closed_issue])
    collector.close_resolved(client, "ContextualWisdomLab/appguardrail", resolutions, False, {closed_issue["title"]: closed_issue})
    assert all(call[0] != "request" for call in client.calls)


def test_close_resolved_dry_run_writes_nothing():
    repo = "ContextualWisdomLab/naruon"
    item = finding(repo=repo, workflow="Strix Security Scan")
    issue = {
        "number": 42,
        "state": "open",
        "title": collector.title(item),
        "body": issueops.marker(repo, "Strix Security Scan", {collector.seen_key(item)}),
    }
    resolutions = {(repo, "Strix Security Scan"): {"repo": repo, "workflow": "Strix Security Scan", "run_url": "https://x/runs/2", "head_sha": "def"}}
    client = FakeClient([issue])
    collector.publish_findings(client, "ContextualWisdomLab/appguardrail", [], True, resolutions)
    assert all(call[0] != "request" for call in client.calls)


def test_list_installation_repos_falls_back_when_token_cannot_list():
    class ExplodingClient:
        def pages(self, path, params=None):
            raise RuntimeError("GitHub API GET /installation/repositories failed: 403 forbidden")

    repos = collector.list_installation_repos(ExplodingClient(), _args())
    assert repos == [{"full_name": "ContextualWisdomLab/appguardrail"}]
