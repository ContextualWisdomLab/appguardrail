# ADR-0003: Unified typed outcomes and gate aggregation

Status: Accepted

Date: 2026-08-09

Implementation: workflow `DetectionResult` and family `FamilyAssessment`
classifiers `ACTIVE_PR/PARTIAL`; one unified cause model is `MISSING`.

## Context

The active PR has two non-isomorphic result models. Workflow classification can
emit finding, clean, control-blocked, dependency-failure, reporting-failed, and
inconclusive results. Family evaluation reduces them to detected, clean, or
unknown, which can discard cause identity and operational meaning.

## Decision

Use one ordered collection of typed outcomes per evaluation. Every assessment
retains issue, claim, cause, detector, evidence, reason code, and one state:

- `finding`;
- `clean`;
- `control_effective` or `control_blocked` with an explicit policy meaning;
- `dependency_failure`;
- `reporting_failure`; or
- `unknown`/`inconclusive`.

Gate aggregation is separate from assessment state. Finding, unknown,
dependency failure, and reporting failure cannot satisfy the direct-efficacy
gate. No first-result, last-write, severity-priority, or family-level collapse
may discard another cause. Duplicate removal is deterministic and output order
does not change the decision.

## Alternatives

1. Keep both models indefinitely: rejected because callers cannot reconstruct
   the same cause set.
2. Treat every operational failure as a finding: rejected as false-positive
   inflation.
3. Treat effective control as clean: rejected because it loses the attempted
   condition and policy action.

## Consequences

Public schemas need a versioned migration, compatibility fixtures, and explicit
consumer handling. Mixed-cause incidents remain reconstructable and gate logic
is testable independently from presentation.

## Acceptance

- All cause combinations preserve typed assessments and stable identity.
- Duplicate and order permutation tests yield the same assessment set/gate.
- #815/#813/#763 source-bound replays preserve operational and semantic causes.
- CLI/JSON/SARIF/HTTP consumers have versioned compatibility evidence.
