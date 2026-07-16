import importlib.util
import subprocess
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


def test_workflow_fails_closed_when_collector_app_is_unconfigured():
    """Keep scheduled collection from reporting green after doing no work."""
    workflow = (
        Path(__file__).resolve().parents[1]
        / ".github"
        / "workflows"
        / "org-security-failure-collector.yml"
    ).read_text(encoding="utf-8")

    assert "vars.ORG_SECURITY_FAILURE_APP_ID || vars.NOEMA_GITHUB_APP_ID" in workflow
    assert (
        "secrets.ORG_SECURITY_FAILURE_APP_PRIVATE_KEY || "
        "secrets.NOEMA_GITHUB_APP_PRIVATE_KEY"
    ) in workflow
    assert "::error::Org security failure collection cannot run" in workflow
    assert "Skipping org security failure collection" not in workflow
    assert "exit 1" in workflow
    assert "if: steps.app-config.outputs.configured == 'true'" not in workflow
    assert "python3 -m scripts.ci.collect_org_security_failures" in workflow
    assert "python3 scripts/ci/collect_org_security_failures.py" not in workflow
    assert "workflow_dispatch:" not in workflow
    assert "repository_dispatch:" in workflow
    assert "types: [collect-org-security-failures]" in workflow
    assert "ORG_SECURITY_FAILURE_DISPATCH_ACTOR" in workflow
    assert "ORG_SECURITY_FAILURE_COLLECTOR_REPOSITORIES" in workflow
    assert "dispatch rejected actor=" in workflow
    assert "DISPATCH_ACTOR: ${{ github.triggering_actor }}" in workflow
    assert "DISPATCH_ACTOR: ${{ github.actor }}" not in workflow
    assert "retain the original dispatch identity" in workflow
    assert "ref: ${{ github.sha }}" in workflow
    assert "persist-credentials: false" in workflow
    assert "Create allowlisted organization read token" in workflow
    assert (
        "repositories: ${{ env.ORG_SECURITY_FAILURE_COLLECTOR_REPOSITORIES }}"
        in workflow
    )
    assert "Create target-only issue write token" in workflow
    assert "repositories: appguardrail" in workflow
    assert "repositories: ${{ github.event.repository.name }}" not in workflow
    assert "An empty value" in workflow
    assert "GH_READ_TOKEN: ${{ steps.read-app-token.outputs.token }}" in workflow
    assert "GH_WRITE_TOKEN: ${{ steps.write-app-token.outputs.token }}" in workflow
    assert "GH_TOKEN: ${{ steps.app-token.outputs.token }}" not in workflow


def test_documented_docker_scan_mount_is_read_only():
    """Keep the scanner from receiving write access to the host source tree."""
    dockerfile = (Path(__file__).resolve().parents[1] / "Dockerfile").read_text(
        encoding="utf-8"
    )

    assert '-v "$PWD:/src:ro"' in dockerfile
    assert "--read-only" in dockerfile
    assert "--tmpfs /tmp:rw,nosuid,nodev,noexec" in dockerfile
    assert '-v "$PWD:/src" appguardrail' not in dockerfile


def test_docker_entrypoint_cannot_be_shadowed_by_scanned_repository(tmp_path):
    """Resolve the trusted CLI even when scan input contains a scanner package."""
    root = Path(__file__).resolve().parents[1]
    attacker = tmp_path / "scanner" / "cli"
    attacker.mkdir(parents=True)
    marker = tmp_path / "attacker-executed"
    (attacker.parent / "__init__.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('scanner init')\n",
        encoding="utf-8",
    )
    (attacker / "__init__.py").write_text("", encoding="utf-8")
    (attacker / "appguardrail.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('entrypoint')\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(root / "docker_entrypoint.py"),
            "--version",
        ],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("appguardrail ")
    assert not marker.exists()

    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    assert (root / "scanner").is_dir()
    assert (root / "appguardrail_core").is_dir()
    assert (root / "docker_entrypoint.py").is_file()
    assert "COPY scanner/ scanner/" in dockerfile
    assert "COPY appguardrail_core/ appguardrail_core/" in dockerfile
    assert "COPY docker_entrypoint.py docker_entrypoint.py" in dockerfile
    assert 'ENTRYPOINT ["python", "-I", "/app/docker_entrypoint.py"]' in dockerfile
    assert "python -I /app/docker_entrypoint.py --help" in dockerfile
    assert 'ENTRYPOINT ["python", "-m", "scanner.cli.appguardrail"]' not in dockerfile


def test_collector_main_separates_org_reads_from_target_issue_writes(monkeypatch):
    """Use distinct clients so the write credential cannot mutate every read target."""
    clients = []

    class RecordingGitHub:
        def __init__(self, token):
            self.token = token
            clients.append(self)

    observed = {}

    def fake_collect(client, _args):
        observed["read"] = client.token
        return [finding()]

    def fake_publish(client, target_repo, findings, dry_run):
        observed["write"] = client.token
        observed["target"] = target_repo
        observed["findings"] = findings
        observed["dry_run"] = dry_run

    monkeypatch.setenv("GH_READ_TOKEN", "allowlisted-read-token")
    monkeypatch.setenv("GH_WRITE_TOKEN", "target-only-write-token")
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(collector, "GitHub", RecordingGitHub)
    monkeypatch.setattr(collector, "collect_findings", fake_collect)
    monkeypatch.setattr(collector, "publish_findings", fake_publish)

    assert collector.main(["--target-repo", "ContextualWisdomLab/appguardrail"]) == 0
    assert [client.token for client in clients] == [
        "allowlisted-read-token",
        "target-only-write-token",
    ]
    assert observed == {
        "read": "allowlisted-read-token",
        "write": "target-only-write-token",
        "target": "ContextualWisdomLab/appguardrail",
        "findings": [finding()],
        "dry_run": False,
    }


@pytest.mark.parametrize(
    ("read_token", "write_token", "reason"),
    [
        ("", "write", "both required"),
        ("read", "", "both required"),
        ("same", "same", "must be distinct"),
    ],
)
def test_collector_main_rejects_missing_or_shared_credentials(
    monkeypatch, read_token, write_token, reason
):
    """Fail closed instead of falling back to one organization-wide write token."""
    monkeypatch.setenv("GH_READ_TOKEN", read_token)
    monkeypatch.setenv("GH_WRITE_TOKEN", write_token)

    with pytest.raises(SystemExit, match=reason):
        collector.main([])


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
    assert client.calls.index(comment[0]) < client.calls.index(patch[0])


def test_publish_retries_after_comment_delivery_failure():
    """Do not persist a dedupe marker until the alert comment is delivered."""
    unseen = finding(job_id=999, snippet="::error:: security failure")
    issue = {
        "number": 17,
        "state": "closed",
        "title": collector.title(unseen),
        "body": issueops.marker(unseen["repo"], unseen["workflow"], {"1:2"}),
    }

    class FailingCommentClient(FakeClient):
        def request(self, method, path, data=None):
            self.calls.append(("request", method, path, data))
            if method == "POST" and path.endswith("/comments"):
                raise RuntimeError("GitHub API comment failed: 503")
            raise AssertionError("marker PATCH must not run after comment failure")

    failing_client = FailingCommentClient([issue])
    with pytest.raises(RuntimeError, match="503"):
        collector.publish_one(
            failing_client,
            "ContextualWisdomLab/appguardrail",
            unseen,
            False,
            {issue["title"]: issue},
            set(),
        )

    key = collector.seen_key(unseen)
    assert key not in issueops.parse_marker(issue["body"])["seen"]
    assert all(call[1] != "PATCH" for call in failing_client.calls)

    retry_client = FakeClient([issue])
    collector.publish_one(
        retry_client,
        "ContextualWisdomLab/appguardrail",
        unseen,
        False,
        {issue["title"]: issue},
        set(),
    )
    assert [call[1] for call in retry_client.calls] == ["POST", "PATCH"]
    assert key in issueops.parse_marker(issue["body"])["seen"]


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


def test_github_client_pins_api_origin_and_rejects_redirects(monkeypatch):
    """Never send the collector bearer token to a caller-selected host."""
    observed = {}

    class FakeResponse:
        headers = {"content-type": "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b'{"ok": true}'

    class FakeOpener:
        def open(self, request, timeout):
            observed["url"] = request.full_url
            observed["authorization"] = request.get_header("Authorization")
            observed["timeout"] = timeout
            return FakeResponse()

    def fake_build_opener(*handlers):
        observed["handlers"] = handlers
        return FakeOpener()

    monkeypatch.setattr(collector.urllib.request, "build_opener", fake_build_opener)
    client = collector.GitHub("sensitive-token")

    assert client.request("GET", "/rate_limit") == {"ok": True}
    assert observed == {
        "handlers": (collector.NoRedirect,),
        "url": "https://api.github.com/rate_limit",
        "authorization": "Bearer sensitive-token",
        "timeout": 30,
    }
    with pytest.raises(TypeError):
        collector.GitHub("token", "https://attacker.invalid")
    with pytest.raises(ValueError, match="path must start"):
        client.request("GET", "https://attacker.invalid/")


def test_build_finding_uses_only_non_sensitive_failure_metadata():
    """Never copy source job logs, step names, or other attacker strings into issues."""
    run = {
        "id": 28492006630,
        "name": "Strix Security Scan",
        "html_url": "https://github.com/ContextualWisdomLab/naruon/actions/runs/28492006630",
        "head_branch": "develop",
        "head_sha": "abc123",
        "event": "pull_request",
        "pull_requests": [{"number": 265}],
    }
    job = {
        "id": 84450511793,
        "name": "strix",
        "html_url": "https://github.com/ContextualWisdomLab/naruon/actions/runs/28492006630/job/84450511793",
        "conclusion": "failure",
        "steps": [
            {
                "number": 2,
                "name": "PRIVATE_SOURCE_MARKER=secret",
                "conclusion": "failure",
            },
            {"number": 3, "name": "ordinary step", "conclusion": "success"},
        ],
    }

    item = collector.build_finding("ContextualWisdomLab/naruon", run, job)

    assert "raw job logs are intentionally not copied" in item["snippet"]
    assert "Job conclusion: failure" in item["snippet"]
    assert "Failed step numbers: 2" in item["snippet"]
    assert "PRIVATE_SOURCE_MARKER" not in item["snippet"]
    assert "secret" not in item["snippet"]
    assert "job_log" not in collector.GitHub.__dict__
