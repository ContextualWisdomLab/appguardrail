# ADR-0001: Issue-complete executable detection contract

Status: Accepted

Date: 2026-08-09

Implementation: `ACTIVE_PR` #911; not on protected `develop` until merged.

## Context

AppGuardrail historically created or retained issues from security workflow
failures. The collector preserved trusted GitHub metadata, but failure metadata
alone could not distinguish a real source finding, a clean scan followed by a
provider outage, an effective authorization block, result publication failure,
or inconclusive evidence. Treating issue presence or workflow conclusion as
detector efficacy would be circular.

The product requirement is stronger: every open or closed AppGuardrail issue,
including manual, automated, product, governance, dependency, infrastructure,
control-block, false-positive, and mixed-cause issues, remains a condition that
AppGuardrail software must directly detect and classify.

## Decision

Adopt a no-exclusion issue→claim→detector-family contract with:

- a complete paginated inventory and normalized requirement digest;
- one or more independently executable claims per issue;
- closed evidence and required-evidence schemas;
- an exact callable production adapter per detector family;
- obligation-level positive, negative, and unknown executions;
- structured provenance binding exact producer, repository, run, head, source,
  evidence reference, digest, and externally provisioned HMAC capability; and
- separate finding, clean, control-effective, dependency-failure,
  reporting-failure, and unknown semantics.

Collectors, labels, issue prose, issue-number registries, substring matching,
and another scanner's opaque pass/fail cannot satisfy the contract. They may
route evidence to a production adapter.

## Alternatives

1. Keep the Actions failure collector only: rejected because it detects a
   failed conclusion, not the underlying condition.
2. Register every issue number with a status fixture: rejected as circular and
   mutation-insensitive.
3. Exclude clean, external, duplicate, or effective-control issues: rejected
   because it narrows the explicit product requirement.
4. One bespoke detector per repeated observation: rejected because identical
   evidence conditions should share reviewed production behavior while
   retaining separate issue claims.

## Consequences

Positive: inventory drift fails closed; multiple causes remain visible;
detector efficacy is testable; operators cannot accidentally report a provider
failure as a vulnerability; source systems can integrate through a stable
envelope.

Negative: the registry is large; new issues cannot pass CI until requirements
and executable coverage are reconciled; external source producers must add a
trusted structured adapter before they can prove clean/finding states.

## Security and privacy consequences

Raw logs and keys stay outside the registry. Bounded provenance and hashes are
retained. HMAC is a producer/run binding capability, not an identity system;
key distribution and rotation remain deployment responsibilities. Unknown
evidence blocks the gate and is not converted to a finding.

## Failure and recovery

If the live audit fails, do not edit the inventory to exclude the issue. Fetch
the exact changed requirement, update claim/detector/test/docs together, and
rerun. If a producer envelope fails verification, preserve it as unknown,
rotate or repair the producer capability, and reissue evidence for the exact
head. Rollback is a single PR revert because there is no data migration.

## Acceptance

- Complete live inventory equality and requirement-digest equality.
- Callable adapter resolution for every family and claim.
- Mutation-sensitive positive, negative, malformed, missing, extra-field,
  provenance-tamper, and multi-cause tests.
- Exact statement/branch coverage and public docstring gates.
- Exact-head CI, security review, packaging, and protected-main live audit.

## Supersession

A successor ADR is required to change no-exclusion scope, outcome authority,
provenance binding, adapter execution semantics, or persistence. Expanding a
family without changing these authorities may update this record and its
traceability row.
