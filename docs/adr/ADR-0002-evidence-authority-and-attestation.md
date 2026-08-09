# ADR-0002: Evidence authority and attestation boundary

Status: Accepted

Date: 2026-08-09

Implementation: shared-HMAC workflow observation `ACTIVE_PR`; source authority,
repository/source-artifact binding, and production acquisition `MISSING`.

## Context

A signed result can authenticate who supplied a bounded payload without proving
that AppGuardrail observed or recomputed the underlying condition. The active
envelope binds producer, run, head, evidence reference, payload digest, and
HMAC, but does not bind repository or source artifact and uses shared
capability keys.

## Decision

Direct efficacy requires source authority, not issue or producer assertion.
Each cause must bind:

- repository, source revision, workflow/run/job/attempt/event, and artifact;
- a reviewed `probe_ref`/`acquirer_ref` that obtains bounded evidence from the
  authoritative repository, API, database, or artifact;
- a versioned native detector that recomputes its outcome;
- producer-specific trust material with rotation and replay boundaries; and
- evidence reference, digest, detector version, and bounded provenance retained
  without centralizing raw logs or secret key material.

Missing, malformed, stale, cross-repository, wrong-source, unauthenticated, or
inaccessible evidence returns unknown and cannot satisfy a clean or efficacy
gate. A shared-HMAC opaque outcome remains classifier input only.

## Alternatives

1. Trust an upstream pass/fail field: rejected as assertion, not detection.
2. Store every raw log centrally: rejected for authority, privacy, and retention
   risk; source owners retain raw evidence.
3. Use one global signing secret: rejected as the target design because it
   expands blast radius and cannot isolate producer identity.

## Consequences

Integrations need explicit source producers and key lifecycle ownership.
Provider or permission failures block only their lane. Repository/source replay
and artifact substitution become testable, while the current envelope remains
honestly classified as partial.

## Acceptance

- Source-bound positive, negative, near-miss, malformed, and replay fixtures.
- Cross-repository/source/job/claim rejection.
- Producer key issue/rotation/revocation procedure and tests.
- Live exact-head acquisition through the same production path.
- No raw authorized log or attestation key in registry, result, or report.
