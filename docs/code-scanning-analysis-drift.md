# Live GitHub Code Scanning analysis drift

AppGuardrail can compare the Code Scanning analysis identities present on a pull request's base branch with the analyses GitHub reports for the exact pull-request head or merge ref. This closes an operational visibility gap that repository-source scanning cannot observe: a tool or category can exist on the default branch while the current pull request has no comparable analysis.

This detector consumes **live GitHub Code Scanning API state**. It is intentionally separate from the repository-local `github-actions-sarif-missing-pull-request-trigger` rule, which inspects workflow text for a local SARIF uploader without a pull-request entry point. The two findings have different evidence, remediation, and deduplication identities.

## Outcomes

Every comparison has one of three statuses:

- **`clean`** — the base branch has at least one healthy analysis identity, pagination is complete, current evidence belongs to the exact head or `refs/pull/<number>/merge`, and every healthy base identity has a healthy current counterpart.
- **`drift`** — complete exact-head evidence confirms that a healthy base identity is missing or the matching current analysis contains a GitHub execution error.
- **`unknown`** — AppGuardrail cannot prove either condition. Permission failures, unavailable Code Scanning, service errors, malformed payloads, pagination limits, empty or unhealthy base evidence, and analyses for another ref or commit all remain unknown rather than becoming false drift findings.

Warnings returned by GitHub are preserved as evidence. A warning does not by itself establish drift, while an analysis `error` means the current identity is not considered healthy.

## Stable analysis identity

The supported GitHub REST response uses the nested `tool.name` field and optional `tool.guid`. AppGuardrail does not depend on the retiring top-level `tool_name` field.

The normalized identity contains:

1. tool name;
2. optional tool GUID;
3. SARIF category;
4. stable analysis-key dimensions; and
5. stable environment or matrix-job dimensions.

Full commit SHAs and Git refs embedded in `analysis_key` or `environment` are normalized so a branch run and its pull-request run can compare. Matrix dimensions such as operating system, language, or runtime version remain distinct. This prevents one successful job from concealing the absence of another expected matrix analysis.

## Exact-head evidence

For each open pull request, the organization collector queries:

- the base branch with `ref=refs/heads/<base>`; and
- pull-request analyses with `pr=<number>`.

A current analysis is accepted only when both conditions hold:

- its ref is the pull-request merge ref `refs/pull/<number>/merge` or the exact head branch ref; and
- its commit SHA is the exact pull-request head SHA or the merge SHA reported by GitHub.

Historical or stale analyses for another head are ignored. If GitHub returns analyses but none match that exact evidence boundary, the outcome is `unknown`, not `drift`.

## Required GitHub App permissions

The read installation token is limited to the reviewed repository allowlist and requires:

- **Actions: read**;
- **Checks: read**;
- **Pull requests: read**; and
- **Code scanning alerts: read** (`security-events: read` in the token action input).

A separate target-only token has **Issues: write** for the AppGuardrail repository. The read and write credentials must be distinct. The collector rejects redirects and pins authenticated requests to `https://api.github.com`.

The scheduled workflow uses the same reviewed organization repository allowlist used by the security-workflow failure collector. This supports standalone AppGuardrail operation while allowing central ContextualWisdomLab governance and naruon-compatible service composition without duplicating policy in every repository.

## Fail-closed transport states

The following conditions produce `unknown` telemetry and no drift issue:

- HTTP `403` or insufficient Code Scanning permissions;
- HTTP `404`, including Code Scanning unavailable for the repository;
- HTTP `503` or another service failure;
- an incomplete or excessive pagination sequence;
- a non-list or malformed API payload;
- malformed pull-request metadata;
- no healthy base analysis;
- no analysis matching the exact head or merge ref.

The collector never copies GitHub response bodies into exception messages or issues. Issue content contains normalized identities, refs, commit SHAs, bounded error text, and remediation only.

## IssueOps behavior

Confirmed drift creates one issue per repository, pull-request number, and exact head SHA. A hidden marker hashes the sorted missing and errored identities, allowing scheduled reruns to remain idempotent. If evidence changes on the same exact head, AppGuardrail updates that issue; a new head receives a new identity. Clean and unknown outcomes are retained in the machine-readable run summary without opening an issue.

The issue explicitly states that it is based on live GitHub state and not inferred from workflow text. Operators should restore the missing tool/category or repair the errored SARIF upload, rerun Code Scanning for the same exact head, and verify a clean comparison before merging.

## Local invocation

Use two GitHub App installation tokens with separate scopes:

```bash
GH_READ_TOKEN='read-installation-token' \
GH_WRITE_TOKEN='target-issue-token' \
python3 -m scripts.ci.collect_code_scanning_drift \
  --owner ContextualWisdomLab \
  --target-repo ContextualWisdomLab/appguardrail \
  --repositories 'appguardrail,naruon' \
  --max-pull-requests 100
```

The command prints a bounded JSON summary containing counts for `clean`, `drift`, `unknown`, total comparisons, and published IssueOps updates. It does not print credentials or raw API response bodies.
