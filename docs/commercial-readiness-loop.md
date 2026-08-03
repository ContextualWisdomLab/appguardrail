# Commercial-readiness loop

AppGuardrail's repository-local commercial-readiness loop turns a reviewed, finite backlog of buyer-visible gaps into ordinary GitHub issues without bypassing pull-request governance.

## Operating contract

The workflow runs once per hour from the reviewed default-branch source. Every pass checks the complete open pull-request queue first. When any pull request is open, the workflow performs no product-gap dispatch. When the queue is empty, it selects the first incomplete gap from the code-reviewed registry, creates at most one active `commercial-readiness` issue, and then applies the `jules` label as a separate event.

A maintainer may also invoke `workflow_dispatch`, but the write-capable job runs only when the selected ref is the repository default branch. Feature-branch workflow code never receives issue-write authority through a manual dispatch.

The issue instructs the implementation agent to use test-driven development, preserve documentation and coverage, update release notes, target `develop`, and submit the result through a normal pull request. Required reviews, checks, branch protection, and the central merge policy remain authoritative.

## Failure recovery

Issue creation and agent handoff are separate GitHub mutations. A process interruption or transient API failure can therefore create the reviewed issue before the `jules` label is applied. The workflow always executes a bounded reconciliation pass after the primary orchestration step. Reconciliation:

- refuses to mutate issue state while any pull request is open;
- recognizes GitHub label payloads in either string or object form;
- restores only the missing `jules` label on a known, marker-bound active gap;
- leaves already-complete handoffs unchanged; and
- preserves the original failure status when the primary orchestration step failed.

This prevents a partial handoff from leaving the commercial-readiness loop permanently stalled.

## Trust boundaries

The workflow uses the repository-scoped `GITHUB_TOKEN` with `contents: read`, `pull-requests: read`, and `issues: write`. It checks out the exact reviewed workflow SHA without persisting credentials. The Python client accepts only `https://api.github.com`, rejects redirects, validates exact `owner/repository` syntax, bounds each GitHub list request to 100 items while following pagination, and never writes source code or merges pull requests.

The gap marker is an exact hidden line whose identifier must exist in the reviewed registry. Arbitrary issues carrying a similar label cannot introduce unreviewed work into the dispatch queue.

## Extending the backlog

Add a new `CommercialGap` entry only through a reviewed pull request. Each entry must contain a descriptive lower-kebab-case identifier, a buyer-visible objective, and bounded acceptance criteria. Keep the registry ordered by commercial impact. Do not describe a finite search as exhaustive or claim evidence that the implementation cannot observe.
