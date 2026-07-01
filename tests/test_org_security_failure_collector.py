import importlib.util
import sys
from pathlib import Path


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
    for name in ("Strix", "OpenCode Review", "AppGuardRail", "Trivy FS", "CodeQL", "Security Process"):
        assert collector.is_security_name(name)
    assert collector.is_security_name("Java CI", "typescript CodeQL analyze")
    assert not collector.is_security_name("pytest", "build")
    assert all(collector.is_failure(value) for value in ("failure", "cancelled", "timed_out", "action_required"))
    assert not any(collector.is_failure(value) for value in ("success", "skipped", None))
    repo, run_id = collector.parse_run_url(
        "https://github.com/ContextualWisdomLab/naruon/actions/runs/28492006630/job/84450511793#step:21:1"
    )
    assert (repo, run_id) == ("ContextualWisdomLab/naruon", 28492006630)


def test_redaction_and_log_compression_prioritize_security_context():
    secret_log = (
        "\x1b[31m2026-07-01T10:20:30.123Z Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz\n"
        "token='github_pat_abcdefghijklmnopqrstuvwxyz0123456789'\n"
        "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature\n"
    )
    redacted = collector.redact(secret_log)
    assert "\x1b" not in redacted
    assert "2026-07-01T10:20:30.123Z" not in redacted
    assert "ghp_" not in redacted and "github_pat_" not in redacted and "eyJhbGci" not in redacted

    log = "\n".join(
        [
            'echo "::error::source branch should not dominate"',
            *[f"noise {i}" for i in range(12)],
            "Unable to map Strix findings",
            "VULN-0001 CRITICAL browser storage issue",
            "RateLimitError: retry budget exhausted",
            *[f"tail noise {i}" for i in range(12)],
            "::error::actual security failure",
        ]
    )
    snippet = collector.compress_log(log, max_lines=28, max_chars=5000)
    assert "VULN-0001 CRITICAL" in snippet
    assert "RateLimitError" in snippet
    assert "::error::actual security failure" in snippet
    assert 'echo "::error::source branch should not dominate"' not in snippet
    assert "...[compressed]" in snippet


def test_marker_body_and_replacement_round_trip():
    item = finding()
    body = collector.issue_body(item, {collector.seen_key(item)})
    assert "<!-- appguardrail-org-security-failure:" in body
    assert "Automated collection of security workflow failures across ContextualWisdomLab." in body
    assert "- Repository: `ContextualWisdomLab/naruon`" in body
    assert "VULN-0001 CRITICAL example" in body

    replaced = collector.replace_marker(body, item["repo"], item["workflow"], {"1:2", "3:4"})
    assert collector.parse_marker(replaced)["seen"] == ["1:2", "3:4"]


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


def test_publish_skips_duplicate_and_reopens_closed_issue():
    item = finding()
    issue = {
        "number": 17,
        "state": "open",
        "title": collector.title(item),
        "body": collector.marker(item["repo"], item["workflow"], {collector.seen_key(item)}),
    }
    client = FakeClient([issue])
    collector.publish_one(client, "ContextualWisdomLab/appguardrail", item, True, {issue["title"]: issue}, set())
    assert all(call[0] != "request" for call in client.calls)

    unseen = finding(job_id=999, snippet="::error:: security failure")
    closed = dict(issue, state="closed", body=collector.marker(item["repo"], item["workflow"], {"1:2"}))
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
        [finding(run_id=1, job_id=10), finding(run_id=2, job_id=20)],
        dry_run=True,
    )
    output = capsys.readouterr().out
    assert client.calls.count(("pages", "/repos/ContextualWisdomLab/appguardrail/issues", {"state": "all", "labels": collector.ISSUE_LABEL})) == 1
    assert output.count("DRY_RUN label ContextualWisdomLab/appguardrail") == 3
    assert "DRY_RUN create issue" in output
    assert "DRY_RUN update issue #dry-run" in output
