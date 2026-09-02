# Commercial-readiness loop

AppGuardrail's repository-local commercial-readiness loop turns a reviewed, finite backlog of buyer-visible gaps into ordinary GitHub issues and one protected implementation pull request at a time. It does not bypass pull-request governance, independent review, exact-head Checks, or branch protection.

## Operating contract

The workflow runs once per hour from the reviewed default-branch source at `17 * * * *`. Every pass checks the complete open pull-request queue first. When any pull request is open, the workflow performs no product-gap dispatch. When the queue is empty, it either selects one existing validated `commercial-readiness` issue or creates the first incomplete gap from the code-reviewed `COMMERCIAL_GAPS` registry.

A maintainer may also invoke `workflow_dispatch`, but the write-capable job runs only when the selected ref is the repository default branch. Feature-branch workflow code never receives issue, source, or pull-request write authority through a manual dispatch.

The selected issue is a human coordination record, not model instruction authority. Its title must exactly match the reviewed registry entry, its body must contain exactly one known hidden marker, and its issue number must be a positive integer. Unknown, duplicate, or mismatched identities fail closed before the model credential is exposed.

The workflow renders `.commercial-agent-contract.md` from the reviewed default-branch registry, appends the reviewed `commercial_remediation_contract.md` policy, makes the combined file read-only, and records its SHA-256 digest. GitHub issue title, body, and comments are untrusted observations. OpenCode receives only the hashed registry-and-remediation contract as task authority below repository policy files.

OpenCode uses the organization-owned contextual-orchestrator gateway with the fail-closed `orchestrator/free` pool. The workflow passes any available `BYTEZ_API_KEY`, `NVIDIA_NIM_API_KEY`, `NVIDIA_NIM_API_KEY_SUB`, `OPENROUTER_API_KEY`, and `OPENAI_API_KEY` only to the trusted sidecar bootstrap step; OpenCode receives an ephemeral loopback gateway token, never a provider credential. The development agent must create exactly one pull request targeting `develop`. It must not choose a provider, direct endpoint, hardcoded model, or paid fallback, and it must not merge, approve, tag, publish, release, change branch protection, or alter the independent review-agent credential path.

The central sidecar is expected to remove provider bootstrap variables after registering them into its process-local credential store. The immutable central revision currently pinned by this change has not yet demonstrated that process-environment scrub; `ContextualWisdomLab/.github#1742` owns the executable RED/GREEN repair. The consumer must not merge until an immutable repaired central pin is available and adopted.

The workflow uses a non-cancelling single-flight concurrency group. Hourly or manual runs that arrive while a pass is active are serialized rather than terminating the in-flight OpenCode reasoning or tool-execution slice. The repository does not configure `timeout-minutes` for this model-backed job. User cancellation, provider termination, hosted-runner/platform limits, and administrative termination remain distinct stop conditions instead of being conflated with an application model timeout.

Before model execution, the workflow verifies the actual pinned OpenCode executable together with the sidecar exports, bearer-file loader contract, authenticated numeric-loopback gateway, and OpenAI-compatible `GET /v1/models` response. It then records a SHA-256 receipt for the gateway bearer. The post-model disclosure check does not source control-plane shell or receive raw provider secret expressions; it first verifies that the bearer file still matches the trusted pre-model receipt.

## Failure recovery

Issue selection and model execution remain separate bounded steps. A transient provider, test, GitHub, or platform failure can leave the validated coordination issue open without creating a pull request. The next eligible hourly pass may select the same issue only after the prior run has ended and the pull-request queue remains empty.

The compatibility reconciliation command is **read-only reconciliation**. It:

- refuses to select an active gap while any pull request is open;
- validates the exact registry title and exactly one known marker;
- reports `wait-prs`, `wait-gap`, or `noop` without mutating GitHub;
- never adds labels, edits issues, dispatches another model, or touches review-agent credentials; and
- fails closed when the active issue identity is malformed or ambiguous.

This prevents an interrupted pass from creating duplicate implementation work while preserving a deterministic operator-visible recovery state.

## RCA and feasibility gate

The reviewed remediation appendix requires the builder to investigate a failure before changing code. It must refresh the exact head, base, review, Check, workflow, permission, dependency, and external-service evidence; reproduce the smallest relevant failure when possible; classify the causal layer; compare bounded candidate actions; and choose the smallest reversible action that addresses the demonstrated cause.

The feasibility preflight checks the required permission, required secret name, executable or API, environment, compute requirements, branch protection, independent review, writer lease, predecessor state, objective success condition, rollback, and customer or security impact. A capability that was not observed cannot be assumed or manufactured. Identical retries are prohibited unless evidence or operating conditions have changed, and transient retries use bounded backoff.

This is an **instruction-level control** backed by repository contract tests and a hashed read-only prompt artifact. The scheduler **cannot prove external feasibility by prompt alone**: providers, permissions, quotas, hardware, network paths, and GitHub services can change after dispatch. Actual feasibility therefore remains conditional on current repository and workflow evidence, focused reproduction, exact-head verification, and protected GitHub results. The agent must report uncertainty rather than convert missing evidence into a success claim.

When there is no feasible action in the current scope, the builder records the exact blocker, the evidence required to clear it, and the next reevaluation condition. It then continues independent non-conflicting work within the same reviewed gap when such work exists, without racing another writer, weakening a gate, or inventing a credential. After three unsuccessful causal attempts, it must question the architecture instead of stacking another speculative patch.

Every generated implementation pull request must preserve concise `Root-cause analysis`, `Feasibility evidence`, `Selected action and rollback`, and `Verification` sections. These sections make the chosen response reviewable, but they do not replace tests, required Checks, branch protection, or independent review.

## Trust boundaries

The workflow has read-only top-level permissions. The single default-branch builder job receives only the repository write permissions needed to create its coordination issue, branch, and pull request. Checkout uses the exact reviewed workflow SHA and does not persist credentials.

The Python client accepts only `https://api.github.com`, rejects redirects, validates exact `owner/repository` syntax, bounds each GitHub list request to 100 items while following pagination, and fails closed on malformed list or creation responses.

The hidden gap marker is accepted only when its identifier exists in the reviewed registry, occurs exactly once, and accompanies the exact registry title. Arbitrary issue prose, similar labels, comments, quoted documents, webpages, tool output, and model output cannot introduce or widen work.

The OpenCode CLI archive is pinned to version `1.18.13` with SHA-256 `8d500b20fed2d26e537e221895b1a575476571b4f0089bb29fb13eeb8eb9e937`. The central composite action `ContextualWisdomLab/.github/.github/actions/orchestrator-free-sidecar@73b250f568d8892ead48bff85de06a4e3eb34e93` provisions the loopback gateway until the owner-side environment-scrub repair is released. The `commercial-builder` uses only `contextual-orchestrator/orchestrator/free`; external directories, web search, web fetch, and nested agent tasks are denied.

The executable handoff verifier accepts only a literal numeric loopback HTTP origin, rejects credentials, redirects, unexpected base paths, malformed bearer files, CLI version drift, oversized/invalid model catalogs, and empty model inventories. Its bounded HTTP timeout covers only the control-plane `GET /v1/models` handshake; model inference remains without a repository-authored elapsed-time deadline.

## Extending the backlog

Add a new `CommercialGap` entry only through a reviewed pull request. Each entry must contain a descriptive lower-kebab-case identifier, a buyer-visible objective, and bounded acceptance criteria. Keep the registry ordered by commercial impact. Do not describe a finite search as exhaustive or claim evidence that the implementation cannot observe.

A completed implementation must remove its finished registry entry only through review and append the next evidence-backed buyer-visible gap when one is supported. New or touched database objects must use descriptive names containing at least two words, preferably `snake_case`.

## Verification and merge boundary

Before the implementation pull request can merge, the same head must pass focused and full tests, exact unrounded 100% statement coverage for changed production modules, complete docstring checks, SAST, security scans, and independent current-head review. The builder must not merge its own pull request. Auto-merge or an explicit SHA-bound merge may act only after repository protection rules are satisfied.

The scheduler contract additionally verifies non-cancelling single-flight concurrency, absence of a repository-authored elapsed-time deadline for model execution, provider-secret expression confinement to the trusted sidecar bootstrap, no post-model control-plane loader execution, bearer-file integrity, and an executable pinned-CLI-to-loopback-gateway handoff. The central sidecar process-environment fix tracked in `ContextualWisdomLab/.github#1742` is an additional immutable dependency gate for this change.

The full credential, recovery, rollback, architecture, and APA 7th source record is maintained in [`opencode-commercial-readiness-agent.md`](opencode-commercial-readiness-agent.md).

## References

GitHub. (2026). *Control the concurrency of workflows and jobs*. GitHub Docs. https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency

Google. (n.d.). *Postmortem culture: Learning from failure*. Site Reliability Engineering Workbook. https://sre.google/workbook/postmortem-culture/

Nelson, A., Rekhi, S., Scarfone, K., & Souppaya, M. (2025). *Incident response recommendations and considerations for cybersecurity risk management: A CSF 2.0 community profile* (NIST Special Publication 800-61 Rev. 3). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-61r3
