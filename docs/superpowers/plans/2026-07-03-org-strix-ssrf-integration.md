# Org Strix And Collector SSRF Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate the still-open AppGuardrail PR #143 and #158 security value into the current `develop` architecture without regressing the sale-readiness core package.

**Architecture:** Keep the reusable scanner and report architecture introduced by `appguardrail_core`; do not merge stale branches that predate that split. Port only the validated Strix/Sentinel detection rules and GitHub job-log redirect hardening into the current files with focused regression tests.

**Tech Stack:** Python 3, pytest, GitHub Actions collector script, AppGuardrail regex scanner, `appguardrail_core` IssueOps helpers.

## Global Constraints

- Do not use Figma Code Connect.
- Do not stage or modify the unrelated `.Jules/palette.md` worktree change.
- Treat review process and queued GitHub checks as non-blocking after local verification.
- Preserve the org ruleset intent; if rulesets must be relaxed for merge, restore exact captured behavior immediately after merge.
- CodeGraph is optional; this worktree has no `.codegraph/` index, so use direct file inspection for this implementation.

---

### Task 1: Port Strix/Sentinel Scanner Patterns

**Files:**
- Modify: `scanner/cli/appguardrail.py`
- Modify: `tests/test_appguardrail.py`

**Interfaces:**
- Consumes: existing `SCAN_RULES` list and `test_scan_file_detects_strix_derived_patterns`.
- Produces: rule IDs `python-okta-host-endswith-ssrf`, `python-subprocess-missing-timeout`, `shell-awk-variable-injection`, `node-exec-url-command-injection`, `node-unvalidated-output-path-write`, `python-expanduser-user-path-traversal`, `github-actions-secret-env-passthrough`, `github-actions-secrets-github-token`, `docker-cli-secret-env-leak`, and `html-target-blank-without-noopener`.

- [ ] **Step 1: Add failing regression samples**

Add these cases to the `samples` dictionary in `test_scan_file_detects_strix_derived_patterns`:

```python
"snowflake.py": {
    "content": (
        "parsed = urlparse(authenticator)\n"
        "if parsed.hostname.endswith('.okta.com'):\n"
        "    return authenticator\n"
    ),
    "ids": {"python-okta-host-endswith-ssrf"},
},
"slow_process.py": {
    "content": "subprocess.run(['ffmpeg', '-i', source_path], check=True)\n",
    "ids": {"python-subprocess-missing-timeout"},
},
"extract-frames.sh": {
    "content": 'awk "BEGIN { print $NUM_FRAMES / $DURATION }"\n',
    "ids": {"shell-awk-variable-injection"},
},
"auth-flow.ts": {
    "content": "exec(authUrl)\n",
    "ids": {"node-exec-url-command-injection"},
},
"export.ts": {
    "content": "writeFileSync(output, contents)\n",
    "ids": {"node-unvalidated-output-path-write"},
},
"audio_separator.py": {
    "content": "audio_file = Path(input_path).expanduser()\n",
    "ids": {"python-expanduser-user-path-traversal"},
},
"strix.yml": {
    "content": (
        "env:\n"
        "  LLM_API_KEY: ${{ secrets.LLM_API_KEY }}\n"
        "  REVIEW_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n"
    ),
    "ids": {
        "github-actions-secret-env-passthrough",
        "github-actions-secrets-github-token",
    },
},
"backup.sh": {
    "content": 'docker run -e DB_PASS="$DB_PASS" postgres:16\n',
    "ids": {"docker-cli-secret-env-leak"},
},
"index.html": {
    "content": '<a href="https://example.com" target="_blank">external</a>\n',
    "ids": {"html-target-blank-without-noopener"},
},
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run:

```bash
pytest -q tests/test_appguardrail.py::test_scan_file_detects_strix_derived_patterns
```

Expected before implementation: failure showing at least one missing expected rule ID.

- [ ] **Step 3: Add scanner rules**

Add the ten rule dictionaries to `SCAN_RULES` after `python-absolute-path-traversal-check-missing`. Each rule must include `id`, compiled `pattern`, `severity`, `message` with OWASP/CWE context, and precise `extensions`.

- [ ] **Step 4: Re-run focused scanner tests**

Run:

```bash
pytest -q tests/test_appguardrail.py::test_scan_file_detects_strix_derived_patterns
```

Expected after implementation: `1 passed`.

### Task 2: Harden GitHub Job Log Redirect Fetching

**Files:**
- Modify: `scripts/ci/collect_org_security_failures.py`
- Modify: `tests/test_org_security_failure_collector.py`

**Interfaces:**
- Consumes: `GitHub.job_log(repo: str, job_id: int) -> str`.
- Produces: safe handling for redirect locations before network download, blocking non-HTTP schemes and internal hostnames.

- [ ] **Step 1: Add focused SSRF tests**

Add tests that patch the collector opener/urlopen path to return dangerous redirect locations and assert that `job_log` returns a safe error instead of fetching:

```python
def test_job_log_rejects_dangerous_redirect_scheme(monkeypatch):
    client = collector.GitHub("token")
    monkeypatch.setattr(collector.urllib.request, "build_opener", lambda *_: FakeRedirectOpener("file:///etc/passwd"))
    assert "Invalid or dangerous URL scheme" in client.job_log("ContextualWisdomLab/naruon", 123)


def test_job_log_rejects_internal_redirect_host(monkeypatch):
    client = collector.GitHub("token")
    monkeypatch.setattr(collector.urllib.request, "build_opener", lambda *_: FakeRedirectOpener("http://169.254.169.254/latest/meta-data"))
    assert "Access to internal address blocked" in client.job_log("ContextualWisdomLab/naruon", 123)
```

- [ ] **Step 2: Run the focused collector tests and verify they fail**

Run:

```bash
pytest -q tests/test_org_security_failure_collector.py
```

Expected before implementation: new SSRF tests fail because dangerous redirect locations are not rejected.

- [ ] **Step 3: Add URL safety helpers**

Implement helpers in `scripts/ci/collect_org_security_failures.py`:

```python
BLOCKED_LOG_HOSTS = {"localhost", "127.0.0.1", "169.254.169.254", "0.0.0.0", "::1"}


class SecureRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_log_download_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _redacted_url(parsed: urllib.parse.ParseResult) -> str:
    return f"{parsed.scheme}://{parsed.hostname or ''}{parsed.path}"


def _validate_log_download_url(url: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise urllib.error.URLError(
            f"Invalid or dangerous URL scheme in location: {_redacted_url(parsed)}"
        )
    if parsed.hostname in BLOCKED_LOG_HOSTS:
        raise urllib.error.URLError(
            f"Access to internal address blocked: {_redacted_url(parsed)}"
        )
    return parsed
```

- [ ] **Step 4: Use secure opener in `GitHub.job_log`**

After resolving the redirect `location`, call `_validate_log_download_url(location)`, then download with:

```python
download_req = urllib.request.Request(location, headers={"User-Agent": UA})
opener = urllib.request.build_opener(SecureRedirectHandler)
with opener.open(download_req, timeout=30) as res:
    return res.read().decode("utf-8", errors="replace")
```

Catch `urllib.error.URLError` and return `Could not fetch job log: {exc.reason}`.

- [ ] **Step 5: Re-run focused collector tests**

Run:

```bash
pytest -q tests/test_org_security_failure_collector.py
```

Expected after implementation: all collector tests pass.

### Task 3: Verify, Publish, And Merge

**Files:**
- Modify: PR branch metadata only through GitHub CLI/API.

**Interfaces:**
- Consumes: local branch `codex/org-strix-ssrf-integration`.
- Produces: merged PR into `develop` with rulesets restored if temporarily relaxed.

- [ ] **Step 1: Run validation**

Run:

```bash
python3 -m py_compile scanner/cli/appguardrail.py scripts/ci/collect_org_security_failures.py
pytest -q
python3 scanner/cli/appguardrail.py scan .
git diff --check
```

Expected: all commands exit `0`; AppGuardrail scan reports zero deploy blockers.

- [ ] **Step 2: Commit**

Stage only implementation, test, and plan files:

```bash
git add scanner/cli/appguardrail.py tests/test_appguardrail.py scripts/ci/collect_org_security_failures.py tests/test_org_security_failure_collector.py docs/superpowers/plans/2026-07-03-org-strix-ssrf-integration.md
git commit -m "Integrate org Strix patterns and secure log fetches"
```

- [ ] **Step 3: Push and create PR**

Run:

```bash
git push -u origin codex/org-strix-ssrf-integration
gh pr create --repo ContextualWisdomLab/appguardrail --base develop --head codex/org-strix-ssrf-integration --title "Integrate org Strix patterns and secure log fetches" --body-file /tmp/appguardrail-org-strix-ssrf-pr.md
```

- [ ] **Step 4: Merge under user policy**

If the PR is locally verified but blocked only by review process or queued checks, merge under the current user policy. If rulesets require temporary relaxation, capture, relax only the needed rules, merge, then restore and diff-check the restored rulesets.
