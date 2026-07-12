from appguardrail_core import issueops


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


def test_security_scope_conclusions_and_run_url_pattern():
    for name in (
        "Strix",
        "OpenCode Review",
        "AppGuardRail",
        "Trivy FS",
        "CodeQL",
        "Security Process",
    ):
        assert issueops.is_security_name(name)
    assert issueops.is_security_name("Java CI", "typescript CodeQL analyze")
    assert not issueops.is_security_name("pytest", "build")
    assert all(
        issueops.is_failure(value)
        for value in ("failure", "cancelled", "timed_out", "action_required")
    )
    assert not any(issueops.is_failure(value) for value in ("success", "skipped", None))
    repo, run_id = issueops.parse_run_url(
        "https://github.com/ContextualWisdomLab/naruon/actions/runs/28492006630/job/84450511793#step:21:1"
    )
    assert (repo, run_id) == ("ContextualWisdomLab/naruon", 28492006630)


def test_redaction_and_log_compression_prioritize_security_context():
    secret_log = (
        "\x1b[31m2026-07-01T10:20:30.123Z Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz\n"
        "token='github_pat_abcdefghijklmnopqrstuvwxyz0123456789'\n"
        "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature\n"
    )
    redacted = issueops.redact(secret_log)
    assert "\x1b" not in redacted
    assert "2026-07-01T10:20:30.123Z" not in redacted
    assert (
        "ghp_" not in redacted
        and "github_pat_" not in redacted
        and "eyJhbGci" not in redacted
    )

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
    snippet = issueops.compress_log(log, max_lines=28, max_chars=5000)
    assert "VULN-0001 CRITICAL" in snippet
    assert "RateLimitError" in snippet
    assert "::error::actual security failure" in snippet
    assert 'echo "::error::source branch should not dominate"' not in snippet
    assert "...[compressed]" in snippet


def test_marker_body_and_replacement_round_trip():
    item = finding()
    body = issueops.issue_body(item, {issueops.seen_key(item)})
    assert "<!-- appguardrail-org-security-failure:" in body
    assert (
        "Automated collection of security workflow failures across ContextualWisdomLab."
        in body
    )
    assert "- Repository: `ContextualWisdomLab/naruon`" in body
    assert "VULN-0001 CRITICAL example" in body

    replaced = issueops.replace_marker(
        body, item["repo"], item["workflow"], {"1:2", "3:4"}
    )
    assert issueops.parse_marker(replaced)["seen"] == ["1:2", "3:4"]


def test_label_title_comment_and_seen_key_helpers():
    item = finding(job_id=999, snippet="::error:: security failure")
    key = issueops.seen_key(item)
    assert len(key) == 16 and all(char in "0123456789abcdef" for char in key)
    assert (
        issueops.sanitize_label_value("repo name/with spaces and symbols!")
        == "repo-name-with-spaces-and-symbols"
    )
    assert (
        issueops.title(item)
        == "[security-failure] ContextualWisdomLab/naruon: Strix Security Scan"
    )
    comment = issueops.issue_comment(item)
    assert "New security workflow failure detected." in comment
    assert "::error:: security failure" in comment


def test_seen_key_is_run_stable_but_signature_sensitive():
    # Re-runs of the SAME failure (different run_id/job_id) share a key so the
    # issue is UPDATED, not spammed with a fresh comment each scheduled run.
    first = finding(run_id=1, job_id=1, snippet="::error:: RateLimitError from GitHub Models")
    rerun = finding(run_id=2, job_id=2, snippet="::error:: RateLimitError from GitHub Models")
    assert issueops.seen_key(first) == issueops.seen_key(rerun)
    # A genuinely different failure produces a different key.
    other = finding(run_id=3, job_id=3, snippet="::error:: Trivy found CRITICAL CVE")
    assert issueops.seen_key(other) != issueops.seen_key(first)
    # Volatile ids inside the same error line are normalized away.
    noisy = finding(run_id=9, job_id=9, snippet="::error:: RateLimitError from GitHub Models attempt 4711")
    stable = finding(run_id=8, job_id=8, snippet="::error:: RateLimitError from GitHub Models attempt 22")
    assert issueops.seen_key(noisy) == issueops.seen_key(stable)


def test_resolved_comment_reports_resolving_run():
    comment = issueops.resolved_comment(
        {
            "repo": "ContextualWisdomLab/naruon",
            "workflow": "Strix Security Scan",
            "run_url": "https://github.com/ContextualWisdomLab/naruon/actions/runs/999",
            "head_sha": "deadbeef",
        }
    )
    assert "completed successfully" in comment
    assert "ContextualWisdomLab/naruon" in comment
    assert "actions/runs/999" in comment
    assert "reopen" in comment
