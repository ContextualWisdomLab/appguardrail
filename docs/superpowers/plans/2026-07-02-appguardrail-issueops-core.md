# AppGuardrail IssueOps Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract reusable IssueOps behavior from the org security failure collector into an in-repo `appguardrail_core` package so the CLI, collector, future dashboard, and reports can share redaction, log compression, issue markers, and duplicate suppression.

**Architecture:** Keep this repository as a monorepo and introduce `appguardrail_core` as an internal package. The existing collector remains the GitHub API orchestration layer; pure text/marker/finding helpers move to `appguardrail_core.issueops`.

**Tech Stack:** Python 3.9+, stdlib only, pytest, setuptools package discovery.

---

## File Structure

- Create: `appguardrail_core/__init__.py`
  - Package marker and public version-independent description.
- Create: `appguardrail_core/issueops.py`
  - Pure IssueOps helpers: security workflow matching, failure conclusion
    matching, run URL parsing, label sanitization, redaction, log compression,
    marker parsing/replacement, summary/body/comment formatting.
- Modify: `scripts/ci/collect_org_security_failures.py`
  - Keep GitHub API client, collection loop, issue publishing, and CLI args.
  - Import IssueOps helpers from `appguardrail_core.issueops`.
- Modify: `pyproject.toml`
  - Include `appguardrail_core*` in setuptools package discovery.
- Create: `tests/test_issueops_core.py`
  - Unit tests for pure core helpers.
- Modify: `tests/test_org_security_failure_collector.py`
  - Keep collector integration/publish tests, importing pure helper behavior
    through the collector module where compatibility matters.
- Modify: `docs/product/2026-07-02-2b-krw-sale-readiness-plan.md`
  - Mark WS4 first slice as started/implemented after code lands.

## Task 1: Add Core Package And Pure IssueOps Tests

**Files:**
- Create: `appguardrail_core/__init__.py`
- Create: `appguardrail_core/issueops.py`
- Create: `tests/test_issueops_core.py`
- Modify: `pyproject.toml`

- [ ] **Step 1: Write the failing core tests**

Create `tests/test_issueops_core.py` with:

```python
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
    for name in ("Strix", "OpenCode Review", "AppGuardRail", "Trivy FS", "CodeQL", "Security Process"):
        assert issueops.is_security_name(name)
    assert issueops.is_security_name("Java CI", "typescript CodeQL analyze")
    assert not issueops.is_security_name("pytest", "build")
    assert all(issueops.is_failure(value) for value in ("failure", "cancelled", "timed_out", "action_required"))
    assert not any(issueops.is_failure(value) for value in ("success", "skipped", None))
    repo, run_id = issueops.parse_run_url(
        "https://github.com/ContextualWisdomLab/naruon/actions/runs/28492006630/job/84450511793#step:21:1"
    )
    assert (repo, run_id) == ("ContextualWisdomLab/naruon", 28492006630)


def test_redaction_and_log_compression_prioritize_security_context():
    secret_log = (
        "\x1b[31m2026-07-01T10:20:30.123Z Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz\n"
        "token='github_pat_abcdefghijklmnopqrstuvwxyz0123456789'\n"
        "jwt=fakejwt_eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature\n"
    )
    redacted = issueops.redact(secret_log)
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
    assert "Automated collection of security workflow failures across ContextualWisdomLab." in body
    assert "- Repository: `ContextualWisdomLab/naruon`" in body
    assert "VULN-0001 CRITICAL example" in body

    replaced = issueops.replace_marker(body, item["repo"], item["workflow"], {"1:2", "3:4"})
    assert issueops.parse_marker(replaced)["seen"] == ["1:2", "3:4"]


def test_label_title_comment_and_seen_key_helpers():
    item = finding(job_id=999, snippet="::error:: security failure")
    assert issueops.seen_key(item) == "28492006630:999"
    assert issueops.sanitize_label_value("repo name/with spaces and symbols!") == "repo-name-with-spaces-and-symbols"
    assert issueops.title(item) == "[security-failure] ContextualWisdomLab/naruon: Strix Security Scan"
    comment = issueops.issue_comment(item)
    assert "New security workflow failure detected." in comment
    assert "::error:: security failure" in comment
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
pytest tests/test_issueops_core.py -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'appguardrail_core'`.

- [ ] **Step 3: Create `appguardrail_core/__init__.py`**

Create:

```python
"""Reusable AppGuardrail core helpers."""
```

- [ ] **Step 4: Create `appguardrail_core/issueops.py`**

Move the pure constants and helper functions from
`scripts/ci/collect_org_security_failures.py` into this module:

```python
from __future__ import annotations

import json
import re
from typing import Any

FAILURES = {"failure", "cancelled", "timed_out", "action_required"}
SECURITY_TERMS = ("strix", "opencode", "appguardrail", "trivy", "codeql", "security process")
MARKER_PREFIX = "<!-- appguardrail-org-security-failure:"
MARKER_SUFFIX = "-->"
DEFAULT_MAX_LOG_CHARS = 30_000
DEFAULT_MAX_LOG_LINES = 200

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
TS_RE = re.compile(r"^\ufeff?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s*")
SECRET_RE = [
    re.compile(r"(?i)(authorization:\s*(?:bearer|token)\s+)[^\s]+"),
    re.compile(r"(?i)\b((?:api[_-]?key|token|secret|password|private[_-]?key)\s*[:=]\s*)['\"]?[^'\"\s]+"),
    re.compile(r"\b(?:gh[opsu]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9]{20,})\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
]
PRIMARY_LOG_RE = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"^\s*::error::",
        r"traceback",
        r"vuln-",
        r"\bcritical\b",
        r"\bhigh\b",
        r"ratelimiterror",
        r"unable to map strix findings",
        r"\btimeout\b|\btimed out\b",
    )
]
FALLBACK_LOG_RE = [re.compile(r"\bfailed\b|\berror\b|\bfatal\b", re.IGNORECASE)]
```

Then add the functions with the same behavior as the collector currently has:
`is_failure`, `is_security_name`, `parse_run_url`, `sanitize_label_value`,
`redact`, `log_ranges`, `compress_log`, `seen_key`, `marker`, `parse_marker`,
`replace_marker`, `title`, `summary`, `issue_body`, and `issue_comment`.

- [ ] **Step 5: Update package discovery**

Modify `pyproject.toml`:

```toml
[tool.setuptools.packages.find]
where = ["."]
include = ["scanner*", "appguardrail_core*"]
namespaces = false
```

- [ ] **Step 6: Run core tests**

Run:

```bash
pytest tests/test_issueops_core.py -q
```

Expected: PASS.

- [ ] **Step 7: Commit**

Run:

```bash
git add appguardrail_core tests/test_issueops_core.py pyproject.toml
git commit -m "feat: add issueops core helpers"
```

Expected: commit succeeds without staging `.Jules/palette.md`.

## Task 2: Update Collector To Use Core Helpers

**Files:**
- Modify: `scripts/ci/collect_org_security_failures.py`
- Modify: `tests/test_org_security_failure_collector.py`

- [ ] **Step 1: Replace collector helper definitions with imports**

In `scripts/ci/collect_org_security_failures.py`, keep GitHub API, time
helpers, collection, publishing, args, and `main`. Import these names:

```python
from appguardrail_core.issueops import (
    DEFAULT_MAX_LOG_CHARS,
    DEFAULT_MAX_LOG_LINES,
    compress_log,
    is_failure,
    is_security_name,
    issue_body,
    issue_comment,
    parse_marker,
    parse_run_url,
    replace_marker,
    sanitize_label_value,
    seen_key,
    title,
)
```

Remove duplicate regex constants and pure helper functions from the collector.

- [ ] **Step 2: Update collector tests to focus on collector compatibility**

In `tests/test_org_security_failure_collector.py`, keep the existing dynamic
module import and publish tests. Replace pure helper tests with imports from
`appguardrail_core.issueops` or leave one compatibility assertion through the
collector module:

```python
def test_collector_reexports_core_matching_for_compatibility():
    assert collector.is_security_name("Strix")
    assert collector.is_failure("failure")
    assert collector.parse_run_url(
        "https://github.com/ContextualWisdomLab/naruon/actions/runs/28492006630/job/84450511793#step:21:1"
    ) == ("ContextualWisdomLab/naruon", 28492006630)
```

- [ ] **Step 3: Run focused tests**

Run:

```bash
pytest tests/test_issueops_core.py tests/test_org_security_failure_collector.py -q
```

Expected: PASS.

- [ ] **Step 4: Run syntax validation**

Run:

```bash
python3 -m py_compile scripts/ci/collect_org_security_failures.py appguardrail_core/issueops.py
```

Expected: command exits 0.

- [ ] **Step 5: Commit**

Run:

```bash
git add scripts/ci/collect_org_security_failures.py tests/test_org_security_failure_collector.py
git commit -m "refactor: reuse issueops core in org collector"
```

Expected: commit succeeds.

## Task 3: Document The First Productization Slice

**Files:**
- Modify: `docs/product/2026-07-02-2b-krw-sale-readiness-plan.md`
- Modify: `README.md`

- [ ] **Step 1: Update product plan WS4**

Under `WS4: IssueOps And Org Collector Productization`, add:

```markdown
First implementation slice:

- Extracted reusable IssueOps helpers into `appguardrail_core.issueops`.
- Kept the GitHub collector as orchestration code only.
- Preserved duplicate suppression, redaction, compressed comments, and Strix
  run URL handling through focused tests.
```

- [ ] **Step 2: Verify README link remains valid**

Run:

```bash
python3 - <<'PY'
from pathlib import Path
assert Path("docs/product/2026-07-02-2b-krw-sale-readiness-plan.md").exists()
assert "2B KRW sale readiness plan" in Path("README.md").read_text()
PY
```

Expected: command exits 0.

- [ ] **Step 3: Commit**

Run:

```bash
git add docs/product/2026-07-02-2b-krw-sale-readiness-plan.md README.md docs/superpowers/plans/2026-07-02-appguardrail-issueops-core.md
git commit -m "docs: record 2b sale readiness plan"
```

Expected: commit succeeds.

## Final Verification

- [ ] **Step 1: Run all tests**

Run:

```bash
pytest -q
```

Expected: all tests pass.

- [ ] **Step 2: Run diff checks**

Run:

```bash
git diff --check
git status --short
```

Expected: `git diff --check` exits 0. `git status --short` may show the
pre-existing `.Jules/palette.md` modification, but no intended files should be
unstaged.

- [ ] **Step 3: Push and open PR**

Run:

```bash
git push -u origin codex/2b-sale-readiness
gh pr create --base develop --head codex/2b-sale-readiness --title "Productize AppGuardrail IssueOps core" --body-file /tmp/appguardrail-2b-sale-readiness-pr.md
```

Expected: PR is created against `develop`.

- [ ] **Step 4: Merge when checks permit**

Run:

```bash
gh pr merge --squash --delete-branch
```

Expected: PR merges unless branch protection, CI failure, or GitHub permission
returns a concrete blocker.
