## AppGuardrail Security Guardrails

Apply the repository-wide rules below to all code you generate: authenticate
protected handlers, authorize resource ownership server-side, keep secrets out
of client output, validate untrusted input, bound file/network work, restrict
CORS, and use 401 for unauthenticated and 403 for unauthorized requests.

When the target stack uses the named technology, apply its narrower rule:

1. **Next.js/browser bundles**: Never use `NEXT_PUBLIC_` for secret or service-role keys.
2. **TypeScript input**: Use Zod or an equivalent server-side schema validator.
3. **Stripe**: Verify webhook signatures before processing payment events.
4. **Supabase**: Use server-validated user identity (for example `getUser()`, not a client session assertion) and enable reviewed RLS policies.

AppGuardrail itself is Python 3.11+ and dependency-light. Do not introduce a
JavaScript, Zod, Next.js, or Supabase dependency merely to satisfy an example
for a different stack.

See https://github.com/ContextualWisdomLab/appguardrail for full rules and checklists.

## Repository contract

AppGuardrail is a Python 3.11+ standalone product with optional service
surfaces. Preserve dependency-light CLI use and versioned JSON/SARIF/HTTP
boundaries. Start architecture work at `ARCHITECTURE.md`; follow the linked PRD,
TRD, ADR, UML, ERD, threat model, test strategy, operability, incident, and
traceability records.

- A collector is not a detector. Do not count issue mirroring, workflow status,
  title/body matching, regex over logs, registry presence, or an opaque external
  scanner result as AppGuardrail direct efficacy.
- Direct source-bound detection requires an atomic cause, trusted probe/acquirer,
  independent oracle corpus, typed outcomes, mutation-sensitive test, and live
  exact-head evidence.
- Preserve multiple causes and keep finding, clean, control, dependency,
  reporting, and unknown semantics distinct.
- Keep missing, malformed, stale, inaccessible, and unauthenticated evidence
  fail-closed and unknown; never manufacture a clean result.
- Treat `ACTIVE_PR`, `PARTIAL`, `MISSING`, and
  `IMPLEMENTED_ON_PROTECTED_MAIN` as evidence states, not prose labels.

For issue-detection changes, run the three focused test files listed in
`AGENTS.md`, exact owned statement coverage, the full repository suite, and
`git diff --check`. Exact branch coverage remains a missing gate and must not be
claimed from the line-coverage script.
