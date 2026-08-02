import pytest

from appguardrail_core import issueops


def _finding(**overrides):
    item = {
        "repo": "ContextualWisdomLab/example",
        "workflow": "Strix Security Scan",
        "job_name": "strix",
        "conclusion": "failure",
        "branch": "fix/security",
        "head_sha": "abc123",
        "event": "pull_request",
        "pr_numbers": [7],
        "run_url": "https://github.com/ContextualWisdomLab/example/actions/runs/1",
        "job_url": "https://github.com/ContextualWisdomLab/example/actions/runs/1/job/2",
        "run_id": 1,
        "job_id": 2,
        "snippet": "Trusted metadata",
    }
    item.update(overrides)
    return item


def test_strix_issue_explains_diagnostic_limits_and_resolution():
    body = issueops.issue_body(_finding(), {"1:2"})

    assert "### AppGuardrail diagnosis" in body
    assert "does not prove that a vulnerability was found" in body
    assert "### Recommended resolution" in body
    assert "fix each confirmed finding" in body
    assert "Do not merge while confirmed critical/high findings" in body


def test_opencode_comment_recommends_gate_specific_remediation():
    body = issueops.issue_comment(
        _finding(workflow="OpenCode Review Dispatch", job_name="opencode-review")
    )

    assert "dispatch or permission configuration" in body
    assert "GitHub App installation" in body
    assert "add regression coverage" in body


def test_timeout_diagnosis_adds_timeout_specific_next_step():
    body = issueops.diagnosis(
        _finding(workflow="CodeQL", job_name="analyze", conclusion="timed_out")
    )

    assert "insufficient to distinguish" in body
    assert "runner capacity and configured timeouts" in body


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


@pytest.mark.parametrize(
    ("log", "expected"),
    [
        ("api_key: 'secret123'", "api_key: [REDACTED]"),
        ('api_key: "secret123"', "api_key: [REDACTED]"),
        ("password='secret with spaces'", "password=[REDACTED]"),
        ('token: "secret with spaces"', "token: [REDACTED]"),
        ("private-key: secret123'", "private-key: [REDACTED]"),
        (r"secret='value with \' quote'", "secret=[REDACTED]"),
        ('secret="value with \\" quote"', "secret=[REDACTED]"),
    ],
)
def test_redact_consumes_complete_quoted_secret(log, expected):
    assert issueops.redact(log) == expected
    assert "secret123" not in issueops.redact(log)


def test_redact_handles_multiple_assignments_without_consuming_field_names():
    log = "api_key: 'first value' password=second token: \"third value\""

    assert issueops.redact(log) == (
        "api_key: [REDACTED] password=[REDACTED] token: [REDACTED]"
    )


def test_redact_fails_closed_for_unterminated_quoted_secret():
    assert issueops.redact("password='secret value without closing quote") == (
        "password=[REDACTED]"
    )


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
    assert issueops.seen_key(item) == "28492006630:999"
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
