import importlib.util
import sys
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "ci"
    / "collect_org_security_failures.py"
)
SPEC = importlib.util.spec_from_file_location("collect_org_security_failures", MODULE_PATH)
collector = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = collector
assert SPEC.loader is not None
SPEC.loader.exec_module(collector)


def make_finding(**overrides):
    values = {
        "repo": "ContextualWisdomLab/naruon",
        "workflow": "Strix Security",
        "run_id": 28492006630,
        "run_url": "https://github.com/ContextualWisdomLab/naruon/actions/runs/28492006630",
        "job_id": 84450511793,
        "job_name": "strix",
        "job_url": (
            "https://github.com/ContextualWisdomLab/naruon/actions/runs/28492006630/"
            "job/84450511793"
        ),
        "conclusion": "failure",
        "branch": "develop",
        "head_sha": "abc123",
        "event": "pull_request",
        "pr_numbers": (265,),
        "snippet": "VULN-0001 CRITICAL example",
    }
    values.update(overrides)
    return collector.Finding(**values)


def test_security_name_matching_is_language_independent():
    assert collector.is_security_name("Strix")
    assert collector.is_security_name("OpenCode Review")
    assert collector.is_security_name("AppGuardrail scan")
    assert collector.is_security_name("Trivy FS")
    assert collector.is_security_name("CodeQL")
    assert collector.is_security_name("Security Process")
    assert collector.is_security_name("Java CI", "typescript CodeQL analyze")
    assert not collector.is_security_name("pytest", "build")


def test_failure_conclusion_filter():
    for conclusion in ("failure", "cancelled", "timed_out", "action_required"):
        assert collector.is_failure_conclusion(conclusion)
    for conclusion in ("success", "skipped", "neutral", None):
        assert not collector.is_failure_conclusion(conclusion)


def test_redact_log_removes_ansi_timestamps_and_secret_shapes():
    log = "\x1b[31m2026-07-01T10:20:30.123Z Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz\n"
    log += "token='github_pat_abcdefghijklmnopqrstuvwxyz0123456789'\n"
    log += "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature\n"

    redacted = collector.redact_log(log)

    assert "\x1b" not in redacted
    assert "2026-07-01T10:20:30.123Z" not in redacted
    assert "ghp_" not in redacted
    assert "github_pat_" not in redacted
    assert "eyJhbGci" not in redacted
    assert "[REDACTED]" in redacted


def test_compress_log_prioritizes_strix_and_error_context():
    log_lines = [f"noise {index}" for index in range(20)]
    log_lines += [
        "Unable to map Strix findings",
        "VULN-0001 CRITICAL browser storage issue",
        "RateLimitError: retry budget exhausted",
    ]
    log_lines += [f"tail noise {index}" for index in range(20)]

    snippet = collector.compress_log("\n".join(log_lines), max_lines=12, max_chars=5000)

    assert "Unable to map Strix findings" in snippet
    assert "VULN-0001 CRITICAL" in snippet
    assert "RateLimitError" in snippet
    assert "...[compressed]" in snippet


def test_compress_log_prefers_emitted_error_over_shell_source():
    log = "\n".join(
        [
            'echo "::error::source branch should not dominate"',
            *[f"noise {index}" for index in range(30)],
            "::error::actual security failure",
            "Error: Process completed with exit code 1.",
        ]
    )

    snippet = collector.compress_log(log, max_lines=8, max_chars=5000)

    assert "::error::actual security failure" in snippet
    assert 'echo "::error::source branch should not dominate"' not in snippet


def test_marker_round_trip_and_replace():
    marker = collector.marker_payload(
        "ContextualWisdomLab/naruon", "Strix Security", {"1:2"}
    )
    parsed = collector.parse_marker(f"{marker}\n\nbody")

    assert parsed["repo"] == "ContextualWisdomLab/naruon"
    assert parsed["workflow"] == "Strix Security"
    assert parsed["seen"] == ["1:2"]

    replaced = collector.replace_marker(
        f"{marker}\n\nbody",
        "ContextualWisdomLab/naruon",
        "Strix Security",
        {"1:2", "3:4"},
    )

    assert collector.parse_marker(replaced)["seen"] == ["1:2", "3:4"]
    assert replaced.endswith("body")


def test_parse_run_url_accepts_job_and_step_fragment_pattern():
    repo, run_id = collector.parse_run_url(
        "https://github.com/ContextualWisdomLab/naruon/actions/runs/"
        "28492006630/job/84450511793#step:21:1"
    )

    assert repo == "ContextualWisdomLab/naruon"
    assert run_id == 28492006630


def test_issue_body_contains_hidden_seen_marker_and_summary():
    finding = make_finding()
    body = collector.issue_body(finding, {finding.seen_key})

    assert "<!-- appguardrail-org-security-failure:" in body
    assert finding.seen_key in body
    assert "Automated collection of security workflow failures across ContextualWisdomLab." in body
    assert "- Repository: `ContextualWisdomLab/naruon`" in body
    assert "VULN-0001 CRITICAL example" in body


class FakeClient:
    def __init__(self, issues):
        self.issues = issues
        self.calls = []

    def paginate(self, path, params=None):
        self.calls.append(("paginate", path, params))
        if path.endswith("/issues"):
            return self.issues
        return []

    def request(self, method, path, data=None, params=None, accept="application/vnd.github+json"):
        self.calls.append(("request", method, path, data, params, accept))
        return {}


def test_publish_skips_duplicate_run_job(capsys):
    finding = make_finding()
    issue = {
        "number": 17,
        "state": "open",
        "title": collector.issue_title(finding.repo, finding.workflow),
        "body": collector.marker_payload(finding.repo, finding.workflow, {finding.seen_key}),
    }
    client = FakeClient([issue])

    collector.publish_finding(
        client,
        "ContextualWisdomLab/appguardrail",
        finding,
        dry_run=True,
        issues_by_title={issue["title"]: issue},
        ensured_labels=set(),
    )

    assert "skip duplicate" in capsys.readouterr().out
    assert all(call[0] != "request" for call in client.calls)


def test_publish_reopens_closed_issue_for_unseen_failure():
    finding = make_finding(job_id=999, snippet="::error:: security failure")
    issue = {
        "number": 17,
        "state": "closed",
        "title": collector.issue_title(finding.repo, finding.workflow),
        "body": collector.marker_payload(finding.repo, finding.workflow, {"1:2"}),
    }
    client = FakeClient([issue])

    collector.publish_finding(
        client,
        "ContextualWisdomLab/appguardrail",
        finding,
        dry_run=False,
        issues_by_title={issue["title"]: issue},
        ensured_labels=set(),
    )

    issue_updates = [
        call
        for call in client.calls
        if call[:3] == ("request", "PATCH", "/repos/ContextualWisdomLab/appguardrail/issues/17")
    ]
    comments = [
        call
        for call in client.calls
        if call[:3]
        == ("request", "POST", "/repos/ContextualWisdomLab/appguardrail/issues/17/comments")
    ]

    assert issue_updates
    assert issue_updates[0][3]["state"] == "open"
    assert finding.seen_key in issue_updates[0][3]["body"]
    assert comments


def test_publish_findings_fetches_existing_issues_once_and_caches_labels(capsys):
    first = make_finding(run_id=1, job_id=10)
    second = make_finding(run_id=2, job_id=20)
    client = FakeClient([])

    collector.publish_findings(
        client,
        "ContextualWisdomLab/appguardrail",
        [first, second],
        dry_run=True,
    )

    issue_fetches = [
        call
        for call in client.calls
        if call == (
            "paginate",
            "/repos/ContextualWisdomLab/appguardrail/issues",
            {"state": "all", "labels": collector.ISSUE_LABEL},
        )
    ]
    output = capsys.readouterr().out

    assert len(issue_fetches) == 1
    assert output.count("DRY_RUN label ContextualWisdomLab/appguardrail") == 3
    assert "DRY_RUN create issue" in output
    assert "DRY_RUN update issue #dry-run" in output
