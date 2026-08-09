# ADR-0004: Independent oracles and mutation proof

Status: Accepted

Date: 2026-08-09

Implementation: registry-owned synthetic fixtures `ACTIVE_PR`; independent
oracle corpus, source-bound black-box tests, and direct efficacy `MISSING`.

## Context

When the production registry supplies both a fixture and its expected result,
the system under test partially defines its own answer. Replaying 20 generic
family/claim semantics across 417 rows proves classifier structure, not that
each historical issue cause is directly detectable.

## Decision

Each claim requires an independent oracle outside the production registry:

- a human-reviewed atomic cause and obligation set;
- sanitized source evidence or a content-addressed fixture derived from the
  authoritative boundary;
- vulnerable, fixed, near-miss, partial, malformed, and unknown cases;
- expected typed assessment and gate decision; and
- mutation proof that inverting/removing the decisive production acquisition,
  predicate, or aggregation logic makes the relevant test fail.

The production registry may route claims and define schemas, but cannot be the
independent oracle. Statement coverage, row counts, signed opaque outcomes, and
fixture-label mutation earn no direct-efficacy credit.

## Alternatives

1. Reuse registry fixtures as golden data: rejected as circular.
2. Review only one example per family: rejected until causal equivalence across
   grouped issues is independently established.
3. Mutate only test data: rejected because production predicates may remain
   ineffective.

## Consequences

The evidence corpus requires review, privacy controls, provenance, and version
maintenance. Detector claims become non-circular and regression-sensitive.
Current direct-efficacy measurements remain 0/417 until this boundary exists.

## Acceptance

- Independent cause manifest and source-evidence corpus for every claim.
- Production probe/acquirer and detector executed end to end.
- Mutation tests kill decisive acquisition, predicate, and gate mutations.
- Exact-head live replay and post-merge protected-main proof.
