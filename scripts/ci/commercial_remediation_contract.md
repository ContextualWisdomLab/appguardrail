
## RCA and feasibility contract

Apply this section whenever a test, Check, review, tool, provider, dependency, permission, timeout, merge, or runtime result fails or behaves unexpectedly. A blocker is a request for investigation, not permission to guess or stop prematurely.

### 1. Establish the root cause from current evidence

- Re-fetch the exact current head SHA, base SHA, branch state, review threads, required Checks, and relevant workflow run before deciding. Never diagnose a predecessor head or stale synthetic merge ref as the current state.
- Read the complete error and reproduce the smallest relevant failure when reproduction is possible. Trace the failing value or state back across each component boundary instead of patching the final symptom.
- Classify the root cause as product code, test or contract, dependency, workflow configuration, authentication or authorization, repository policy, external service, rate limit, runner or queue infrastructure, stale state, superseded work, or an architectural defect. Keep evidence that distinguishes the selected class from the alternatives.
- Treat a queued review, unavailable external service, rate limit, or missing capability as external evidence rather than silently rewriting product code to make the symptom disappear.

### 2. Produce candidate actions

- Write two or three bounded candidate actions when more than one plausible remedy exists. Include doing nothing yet, retrying with changed evidence, changing code or tests, changing workflow configuration, reverting, replacing a dependency, or escalating an external blocker when those are genuinely applicable.
- State what observation would make each candidate succeed or fail. Do not choose an action merely because it is easy to describe.

### 3. Run a feasibility preflight before acting

For every candidate action, verify all applicable facts from the current run:

- The required permission is present in the current token or repository role.
- The required secret is configured by its reviewed name without reading or printing its value. Do not invent a secret, key, token, permission, endpoint, environment, reviewer, or model capability that has not been observed.
- The required tool, executable, API, service, dependency version, runner, hardware target, and network path actually exist and are usable in this execution environment.
- The action fits the remaining time budget, compute budget, API quota, repository size, and provider limit. Split work rather than pretending an unbounded repair can finish inside a bounded run.
- Branch protection, independent review, required Checks, security gates, release policy, and the exact-head merge boundary remain intact.
- The repository writer lease is free: no dedicated loop, live actor, changing head, changing base, changing comment, or other concurrent writer owns the same scope.
- Dependencies and predecessor PRs are present in the required state, or the candidate explicitly handles their absence without fabricating it.
- The action has a focused failing test or other objective reproducer, a measurable success condition, a rollback path, and no larger customer or security regression than the defect it addresses.

Reject a candidate as nonviable when any mandatory fact cannot be established. Record the missing fact instead of converting uncertainty into confidence.

### 4. Execute and verify the smallest viable action

- Select the smallest viable action that addresses the demonstrated root cause, preserves the product contract, and remains reversible.
- For code or behavior changes, create or retain the failing regression test first, observe the expected RED result, implement one causal change, and rerun focused and full verification.
- Do not blindly rerun an identical failed workflow, model call, or command. Retry only when evidence, inputs, configuration, capacity, or the external condition has materially changed, and use bounded backoff for rate limits or transient infrastructure.
- After three unsuccessful causal attempts, stop stacking patches and question the architecture. Record why the current pattern may be unsound before proposing a broader redesign.
- When no feasible action exists inside the current scope, preserve the exact blocker, the evidence needed to clear it, and the next reevaluation condition. Continue with independent non-conflicting work that advances the same reviewed gap without racing another writer or weakening a gate.
- Never report a fix, completed verification, merge readiness, or release readiness without fresh evidence from the exact current head.

### 5. Preserve RCA and feasibility evidence

The pull request description must contain concise sections named `Root-cause analysis`, `Feasibility evidence`, `Selected action and rollback`, and `Verification`. The RCA and feasibility evidence must identify the observed failure, causal evidence, rejected nonviable actions, selected action, required capabilities actually present, objective verification, residual uncertainty, and rollback. Do not include secret values, sensitive logs, or unsupported claims.
