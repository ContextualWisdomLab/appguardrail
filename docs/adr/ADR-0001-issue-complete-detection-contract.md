# ADR-0001: No-exclusion issue inventory and collector boundary

Status: Accepted

Date: 2026-08-09

Implementation: inventory/classifier foundation `ACTIVE_PR` #911; direct
issue-level efficacy remains `MISSING`.

## Context

AppGuardrail historically retained issues created from security workflow
failures. The collector preserved bounded GitHub metadata, but that metadata
could not distinguish a source finding from a provider outage, effective
authorization control, reporting failure, or inconclusive evidence. Excluding
closed, duplicate, operational, or hard-to-instrument issues would hide product
requirements instead of resolving them.

## Decision

Adopt a no-exclusion inventory contract:

- every open and closed AppGuardrail issue remains a retained requirement;
- issue number plus normalized title/body digest detects inventory drift;
- each distinct underlying cause must eventually have an explicit claim;
- collectors, issue prose, labels, workflow conclusions, regexes, and opaque
  upstream outcomes are observations, not direct detectors; and
- blocked evidence remains visible and non-passing rather than becoming clean,
  waived, suppressed, or not applicable without reviewed product-boundary
  evidence.

Independent decisions govern the implementation boundaries:

- [ADR-0002](ADR-0002-evidence-authority-and-attestation.md): source authority
  and attestation;
- [ADR-0003](ADR-0003-typed-outcomes-and-gate-aggregation.md): typed outcomes
  and gate aggregation; and
- [ADR-0004](ADR-0004-independent-oracles-and-mutation-proof.md): independent
  oracle and direct-efficacy proof.

## Alternatives

1. Keep the Actions failure collector only: rejected because it observes a
   failed conclusion, not the underlying condition.
2. Register every issue with a generic family fixture: useful for inventory,
   rejected as direct-efficacy evidence because it is circular.
3. Exclude clean, external, duplicate, closed, or effective-control issues:
   rejected because it narrows the explicit product requirement.

## Consequences

Inventory drift fails closed and no issue silently disappears. The registry is
large, and new/edited issues require atomic claim/test/docs reconciliation.
Inventory completeness does not imply detector completeness: PR #911 has 414
issue identities and 417 rows but only 20 unique family/claim semantics, 0/414
cause-bound issues, 0/417 independently validated direct claims, and 0/414
protected-main operational proofs.

## Acceptance

- Complete paginated open-and-closed inventory equality.
- Exact normalized requirement-digest equality.
- No exclusion/waiver field in the registry contract.
- Separate declared measurements for inventory, cause binding, direct efficacy,
  and protected-main proof.
- Exact-head CI plus a post-merge protected-main audit before any shipped claim.

This ADR accepts the requirement boundary; it does not claim that source
acquisition, direct detectors, independent oracles, or protected-main efficacy
are implemented.
