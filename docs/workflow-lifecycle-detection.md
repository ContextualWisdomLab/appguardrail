# GitHub Actions workflow lifecycle detection

AppGuardrail compares the live GitHub Actions registry with the recursive tree
of one exact default-branch commit. The implementation in
`appguardrail_core.workflow_lifecycle` reuses the reviewed central contract from
`ContextualWisdomLab/.github#945` and PR `ContextualWisdomLab/.github#1026`
(`d17ff23c555580d6e7789049818a452686ae0cba`). It does not disable workflows,
delete source, write branches, or create issues.

Run a live read-only organization inventory with a GitHub App installation
token that can prove complete organization visibility:

```bash
GITHUB_TOKEN=... python -m appguardrail_core.workflow_lifecycle \
  --live \
  --output workflow-lifecycle-ledger.json \
  --receipt-output workflow-lifecycle-receipts.json \
  --failure-output workflow-lifecycle-failure.json \
  --fail-on-orphan-active
```

The detector paginates repositories and workflows, binds every repository to
an unchanged 40-character default-branch SHA, validates the full recursive
tree, and records content hashes for API receipts. It separates
`present_active`, `present_disabled`, `orphan_active`, `orphan_disabled`,
`dynamic_owned`, and `unresolved`. Permission loss, 404 ambiguity, exhausted
5xx retry, malformed data, incomplete pagination, reused workflow IDs, and
branch movement fail closed rather than becoming clean evidence.

The packaged source scanner separately reports two structural writer shapes:

- `github-actions-mutable-branch-writer` detects a write token combined with a
  push to an event-derived mutable branch. An explicit protected-branch target
  does not trigger this rule;
- `github-actions-self-modifying-writer` detects a write-capable workflow that
  edits or deletes `.github/workflows/**`.

Names such as `once`, `apply`, or `repair` are not findings by themselves. A
supported live one-shot file is `present_active`; GitHub-owned `dynamic/**`
records remain `dynamic_owned`. Exact-ID disablement is an operator decision
only after a fresh complete inventory proves the file absent, no active job
owns the identity, and the lifecycle owner approves the action. Production
schedule, security, reusable, and release workflows must never be disabled by
name heuristics.

An orphan count alone does not explain a queue incident. Queue causality needs
separate run, concurrency, runner, and occupancy evidence.
