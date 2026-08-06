# Commercial-readiness loop

AppGuardrail's repository-local commercial-readiness loop turns a reviewed, finite backlog of buyer-visible gaps into ordinary GitHub issues and one protected implementation pull request at a time. It does not bypass pull-request governance, independent review, exact-head Checks, or branch protection.

## Operating contract

The workflow runs once per hour from the reviewed default-branch source at `17 * * * *`. Every pass checks the complete open pull-request queue first. When any pull request is open, the workflow performs no product-gap dispatch. When the queue is empty, it either selects one existing validated `commercial-readiness` issue or creates the first incomplete gap from the code-reviewed `COMMERCIAL_GAPS` registry.

A maintainer may also invoke `workflow_dispatch`, but the write-capable job runs only when the selected ref is the repository default branch. Feature-branch workflow code never receives issue, source, or pull-request write authority through a manual dispatch.

The selected issue is a human coordination record, not model instruction authority. Its title must exactly match the reviewed registry entry, its body must contain exactly one known hidden marker, and its issue number must be a positive integer. Unknown, duplicate, or mismatched identities fail closed before the model credential is exposed.

The workflow renders `.commercial-agent-contract.md` from the reviewed default-branch registry, makes it read-only, and records its SHA-256 digest. GitHub issue title, body, and comments are untrusted observations. OpenCode receives only the registry-derived contract as task authority below repository policy files.

OpenCode uses `NVIDIA_NIM_API_KEY` through the provider variable `NVIDIA_API_KEY`. The development agent must create exactly one pull request targeting `develop`. It must not merge, approve, tag, publish, release, change branch protection, or alter the independent review-agent credential path.

## Failure recovery

Issue selection and model execution remain separate bounded steps. A transient provider, test, or GitHub failure can leave the validated coordination issue open without creating a pull request. The next hourly pass may select the same issue only when the pull-request queue remains empty.

The compatibility reconciliation command is **read-only reconciliation**. It:

- refuses to select an active gap while any pull request is open;
- validates the exact registry title and exactly one known marker;
- reports `wait-prs`, `wait-gap`, or `noop` without mutating GitHub;
- never adds labels, edits issues, dispatches another model, or touches review-agent credentials; and
- fails closed when the active issue identity is malformed or ambiguous.

This prevents an interrupted pass from creating duplicate implementation work while preserving a deterministic operator-visible recovery state.

## Trust boundaries

The workflow has read-only top-level permissions. The single default-branch builder job receives only the repository write permissions needed to create its coordination issue, branch, and pull request. Checkout uses the exact reviewed workflow SHA and does not persist credentials.

The Python client accepts only `https://api.github.com`, rejects redirects, validates exact `owner/repository` syntax, bounds each GitHub list request to 100 items while following pagination, and fails closed on malformed list or creation responses.

The hidden gap marker is accepted only when its identifier exists in the reviewed registry, occurs exactly once, and accompanies the exact registry title. Arbitrary issue prose, similar labels, comments, quoted documents, webpages, tool output, and model output cannot introduce or widen work.

The OpenCode GitHub action is pinned to immutable commit `77fc88c8ade8e5a620ebbe1197f3a572d29ae91a`. The built-in NVIDIA provider is the only enabled model provider for the `commercial-builder`. External directories, web search, web fetch, and nested agent tasks are denied.

## Extending the backlog

Add a new `CommercialGap` entry only through a reviewed pull request. Each entry must contain a descriptive lower-kebab-case identifier, a buyer-visible objective, and bounded acceptance criteria. Keep the registry ordered by commercial impact. Do not describe a finite search as exhaustive or claim evidence that the implementation cannot observe.

A completed implementation must remove its finished registry entry only through review and append the next evidence-backed buyer-visible gap when one is supported. New or touched database objects must use descriptive names containing at least two words, preferably `snake_case`.

## Verification and merge boundary

Before the implementation pull request can merge, the same head must pass focused and full tests, exact unrounded 100% statement coverage for changed production modules, complete docstring checks, SAST, security scans, and independent current-head review. The builder must not merge its own pull request. Auto-merge or an explicit SHA-bound merge may act only after repository protection rules are satisfied.

The full credential, recovery, rollback, architecture, and APA 7th source record is maintained in [`opencode-commercial-readiness-agent.md`](opencode-commercial-readiness-agent.md).
