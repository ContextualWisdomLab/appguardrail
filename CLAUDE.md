## AppGuardrail Security Guardrails

Apply the following security rules to all code you generate:

1. **Authentication**: Check authentication as the first operation in every API handler.
2. **Authorization**: Verify resource ownership (owner_id === session.user.id) server-side.
3. **Secrets**: Never use NEXT_PUBLIC_ prefix on secret keys or service role keys.
4. **Input validation**: Validate all inputs with Zod or equivalent before processing.
5. **Stripe**: Always verify webhook signatures before processing payment events.
6. **Supabase**: Use getUser() (not getSession()) server-side; RLS on all tables.
7. **Files**: Validate type, size, and generate server-side filenames for uploads.
8. **CORS**: Restrict to known origins on authenticated endpoints.

Return 401 for unauthenticated requests, 403 for ownership violations.

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
