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
- Treat AppGuardrail critical/high findings as deploy blockers unless the finding is in docs, tests, examples, or scanner fixtures.

If CodeGraph is available, use it for call graph, blast radius, and ownership-flow checks before broad file reads.

## Commercial-readiness tasks

When an issue carrying the `commercial-readiness` and `jules` labels starts a
task, the reviewed issue body is the authoritative product scope and acceptance
contract. Do not broaden it into unrelated cleanup.

- Write the failing regression test first and preserve 100% docstring and code coverage for changed behavior.
- Target `develop`, include `Closes #<issue number>` in the pull request body, and never bypass required checks, reviews, branch protection, or the central merge policy.
- Update user documentation and the changelog fragment required by the issue.
- Preserve standalone use and modular MSA compatibility with ContextualWisdomLab infrastructure and naruon.
- Record uncertainty explicitly and use current primary documentation, standards, or peer-reviewed evidence rather than unsupported claims.
