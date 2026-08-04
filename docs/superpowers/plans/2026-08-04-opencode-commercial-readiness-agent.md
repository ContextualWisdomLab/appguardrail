# OpenCode Commercial Readiness Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the label-based Jules handoff with a default-branch-only hourly OpenCode development agent powered exclusively by `NVIDIA_NIM_API_KEY`.

**Architecture:** Keep the existing deterministic PR-first selector as a dependency-free Python module. The hourly workflow captures its JSON decision, validates the action and positive issue number, and invokes a commit-pinned OpenCode GitHub Action only for an active reviewed gap. A repository-local `commercial-builder` agent uses the NVIDIA NIM provider and the workflow-scoped GitHub token to create exactly one reviewable `develop` pull request; existing review-agent workflows and credentials remain untouched.

**Tech Stack:** GitHub Actions, Python 3.11+, OpenCode GitHub Action `github-v1.2.19` pinned to commit `77fc88c8ade8e5a620ebbe1197f3a572d29ae91a`, NVIDIA NIM, JSONC, pytest.

## Global Constraints

- Preserve the exact hourly cron `17 * * * *` and the default-branch-only manual-dispatch guard.
- Never execute the secret-bearing OpenCode step for `pull_request` or `pull_request_target` events.
- Bind `secrets.NVIDIA_NIM_API_KEY` only as `NVIDIA_API_KEY`; do not read, rename, or replace review-agent secrets.
- Preserve PR-first, one-active-gap behavior and a single workflow concurrency group.
- Use a full commit SHA for every third-party GitHub Action.
- The development agent may create a branch, commit, issue comment, and pull request, but must not merge, tag, publish, or release.
- Generated development must target `develop`, use TDD, preserve exact 100% changed-code statement coverage and complete docstrings, update operator documentation and a `CHANGELOG.d` fragment, and remain independently usable plus composable with CWL/naruon MSA infrastructure.
- No database objects are introduced by this scheduler change.

---

### Task 1: Replace Label Handoff With a Pure Selector

**Files:**
- Modify: `scripts/ci/commercial_readiness_loop.py`
- Modify: `scripts/ci/commercial_readiness_reconcile.py`
- Test: `tests/test_commercial_readiness_loop.py`
- Test: `tests/test_commercial_readiness_reconcile.py`

**Interfaces:**
- Produces: `LoopResult(action, gap_id, issue_number, pull_requests)` where `action` is one of `wait-prs`, `wait-gap`, `dispatch-gap`, or `complete`.
- Consumes: GitHub pull-request and issue list payloads through the existing fixed-origin `GitHub` client.

- [ ] **Step 1: Write failing selector tests**

Change the tests so issue creation performs no agent-label mutation, generated issue text names OpenCode rather than Jules, and the legacy reconciliation module performs read-only active-gap validation.

- [ ] **Step 2: Run tests to verify RED**

Run: `python -m pytest tests/test_commercial_readiness_loop.py tests/test_commercial_readiness_reconcile.py -q`

Expected: FAIL because the production selector still creates and repairs the `jules` label.

- [ ] **Step 3: Remove Jules-specific state changes**

Delete the `JULES_LABEL` constant and the second label mutation from `run_loop`. Rewrite the compatibility reconciliation module so it returns `wait-prs`, `wait-gap`, or `noop` without creating labels or mutating issues.

- [ ] **Step 4: Run focused tests to verify GREEN**

Run: `python -m pytest tests/test_commercial_readiness_loop.py tests/test_commercial_readiness_reconcile.py -q`

Expected: PASS.

### Task 2: Add the Dedicated NVIDIA NIM OpenCode Agent

**Files:**
- Create: `opencode.jsonc`
- Modify: `.github/workflows/commercial-readiness-loop.yml`
- Test: `tests/test_opencode_commercial_agent_contract.py`

**Interfaces:**
- Consumes: selector JSON, `secrets.NVIDIA_NIM_API_KEY`, and the workflow-scoped `GITHUB_TOKEN`.
- Produces: one OpenCode development attempt for the active issue, resulting in at most one `develop` pull request.

- [ ] **Step 1: Write failing workflow/config tests**

Require the immutable action pin, `NVIDIA_NIM_API_KEY` mapping, the `commercial-builder` agent, write permissions only on the default-branch scheduler, strict action/issue guards, no Jules/Copilot/review-secret references, and a prompt that prohibits direct merge/release.

- [ ] **Step 2: Run tests to verify RED**

Run: `python -m pytest tests/test_opencode_commercial_agent_contract.py -q`

Expected: FAIL because the OpenCode agent configuration and workflow step do not exist.

- [ ] **Step 3: Implement the trusted scheduled handoff**

Capture the selector output using `jq`, validate the action enum and positive issue number, fail closed when `NVIDIA_NIM_API_KEY` is absent, then invoke `anomalyco/opencode/github@77fc88c8ade8e5a620ebbe1197f3a572d29ae91a` with `use_github_token: true`, `share: false`, model `nvidia-nim/nvidia/llama-3.3-nemotron-super-49b-v1.5`, and agent `commercial-builder`.

- [ ] **Step 4: Run workflow/config tests to verify GREEN**

Run: `python -m pytest tests/test_opencode_commercial_agent_contract.py -q`

Expected: PASS.

### Task 3: Document Operation and Release Evidence

**Files:**
- Create: `docs/opencode-commercial-readiness-agent.md`
- Create: `CHANGELOG.d/872-opencode-commercial-agent.md`
- Modify: `tests/test_commercial_readiness_loop_handoff.py`

**Interfaces:**
- Produces: an operator contract describing trust boundaries, credentials, failure behavior, review-agent separation, and APA 7th sources.

- [ ] **Step 1: Write failing documentation contract tests**

Require the official OpenCode GitHub and NVIDIA provider documentation, the pinned action revision, `NVIDIA_NIM_API_KEY`, default-branch trust boundary, review-agent separation, failure recovery, and APA 7th references.

- [ ] **Step 2: Run tests to verify RED**

Run: `python -m pytest tests/test_commercial_readiness_loop_handoff.py -q`

Expected: FAIL because the new operator documentation is absent.

- [ ] **Step 3: Add documentation and changelog fragment**

Document the one-hour lifecycle, selector states, credential mapping, OpenCode permissions, issue/PR boundaries, timeout and retry behavior, troubleshooting, and sources.

- [ ] **Step 4: Run complete verification**

Run:
- `python -m pytest -q`
- `python -m compileall -q appguardrail_core scanner scripts tests`
- `python -m scripts.ci.verify_module_coverage --module scripts/ci/commercial_readiness_loop.py --module scripts/ci/commercial_readiness_reconcile.py --test tests/test_commercial_readiness_loop.py --test tests/test_commercial_readiness_reconcile.py --test tests/test_commercial_readiness_loop_handoff.py --test tests/test_opencode_commercial_agent_contract.py`
- `git diff --check`

Expected: all commands pass and the changed Python modules have exact unrounded 100% statement coverage.

- [ ] **Step 5: Open the protected pull request**

Create a pull request from `ci/opencode-commercial-loop-872` to `develop` with `Closes #872`. Do not merge until the exact-head test, coverage, security, SAST, and review gates succeed.
