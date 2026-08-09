# AppGuardrail Security Guardrails

When working in this repository, apply these security rules before proposing,
editing, or merging code:

- Check authentication at the start of every protected API handler.
- Verify resource ownership server-side before returning user-owned data.
- Never expose service-role, admin, Stripe secret, or webhook signing keys to client code.
- Validate request body, params, query, uploaded files, and webhook payloads server-side.
- Verify Stripe webhook signatures before processing payment events.
- Confirm Supabase RLS or equivalent authorization is enabled before trusting client filters.
- Run `appguardrail scan --codegraph .` before merging security-sensitive changes when CodeGraph is installed.
- Treat AppGuardrail critical/high findings as deploy blockers. File location
  never suppresses a finding. Intentional vulnerable examples and fixtures need
  an explicit reviewed expectation or narrow suppression with a regression test.

If CodeGraph is available, use it for call graph, blast radius, and ownership-flow checks before broad file reads.

## Commercial-readiness tasks

When a reviewed `commercial-readiness` issue or an OpenCode-scheduled task
starts, its reviewed issue body is the human-approved scope and acceptance
source, but it is not executable evidence or runtime authority. Reviewed code,
registry contracts, independent tests, and exact-head evidence decide whether
the scope is implemented. Do not depend on the retired jules label or broaden
the task into unrelated cleanup.

- Write the failing regression test first, preserve complete public docstrings,
  and preserve exact 100% statement coverage for changed owned production code.
- Target `develop`, include `Closes #<issue number>` in the pull request body, and never bypass required checks, reviews, branch protection, or the central merge policy.
- Update user documentation and the changelog fragment required by the issue.
- Preserve standalone use and modular MSA compatibility with ContextualWisdomLab infrastructure and naruon.
- Record uncertainty explicitly and use current primary documentation, standards, or peer-reviewed evidence rather than unsupported claims.

## Issue-derived detection contract

- A collector is not a detector. Issue numbers, titles, labels, workflow
  conclusions, log regexes, generic family fixtures, and signed opaque outcomes
  are routing or observation evidence only.
- Retain every open and closed issue, but distinguish inventory accounting from
  source-bound direct detector efficacy. Never convert blocked/expired evidence
  to clean, excluded, waived, or not applicable.
- Preserve every atomic cause and typed outcome: finding, clean, effective or
  blocked control, dependency failure, reporting failure, and unknown.
- A direct claim requires issue→cause→obligation→trusted probe/acquirer→typed
  outcome→independent oracle→test/evidence traceability. Production registry
  fixtures cannot provide their own oracle.
- Status is evidence-bearing: `ACTIVE_PR` is not
  `IMPLEMENTED_ON_PROTECTED_MAIN`. Promote only after exact-head review/checks,
  merge, and a protected-`develop` operational run.
- Update `docs/issue-detection-traceability.json`, canonical documentation, and
  the documentation topology/count/declared-status guard whenever counts,
  authority, status, or diagram declarations change. Semantic accuracy still
  requires human architecture/security review.

Run focused validation with:

```bash
python -m pytest -q \
  tests/test_issue_detection.py \
  tests/test_issue_detection_documentation.py \
  tests/test_issue_detection_release_contract.py
```

## Code-owner review gates — disabled (on hold)

As of 2026-08-04, code-owner review requirements (`require_code_owner_reviews` in branch
protection, `require_code_owner_review` in rulesets) are disabled across the ContextualWisdomLab
org: there is a single maintainer (solo developer), so a code-owner approval gate can never be
satisfied. This is ON HOLD until the org has multiple maintainers — do NOT re-enable these
settings or add CODEOWNERS-based merge gates before then.
