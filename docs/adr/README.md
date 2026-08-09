# AppGuardrail architecture decisions

ADRs are append-only decisions. Superseded records remain discoverable and
name their successor. Status values are `Proposed`, `Accepted`, `Superseded`,
or `Rejected`. `Accepted` records a decision; each ADR's separate
`Implementation` field states whether protected-main evidence exists.

## Decision index

| ADR | Status | Decision | Implementation |
|---|---|---|---|
| [ADR-0001](ADR-0001-issue-complete-detection-contract.md) | Accepted | No-exclusion issue inventory; collector is not detector. | Inventory/classifier `ACTIVE_PR`; direct efficacy `MISSING` |
| [ADR-0002](ADR-0002-evidence-authority-and-attestation.md) | Accepted | Source authority and attestation boundary. | HMAC observation `ACTIVE_PR`; source binding/acquisition `MISSING` |
| [ADR-0003](ADR-0003-typed-outcomes-and-gate-aggregation.md) | Accepted | Unified typed outcomes and independent gate aggregation. | Two partial classifier models; unification `MISSING` |
| [ADR-0004](ADR-0004-independent-oracles-and-mutation-proof.md) | Accepted | Independent oracle corpus and production mutation proof. | Registry fixtures only; direct efficacy `MISSING` |
| [ADR-0005](ADR-0005-control-plane-persistence-migration-boundary.md) | Accepted | Explicit legacy and canonical-v2 persistence transition. | v2 schema on protected main; serving/recovery integration `PARTIAL` |

Existing narrow design records under `docs/superpowers/specs/` remain useful
implementation history but are not substitutes for status-bearing ADRs. New
changes to trust authority, persistence, external producer contracts, public
result semantics, or efficacy acceptance require an indexed ADR.
