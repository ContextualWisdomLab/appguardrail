# AppGuardrail architecture decisions

ADRs are append-only decisions. Superseded records remain discoverable and
name their successor. Status values are `Proposed`, `Accepted`, `Superseded`,
or `Rejected`.

## Decision index

| ADR | Status | Decision | Implementation |
|---|---|---|---|
| [ADR-0001](ADR-0001-issue-complete-detection-contract.md) | Accepted | Every AppGuardrail issue is a no-exclusion direct-detection target. | Inventory/classifier `ACTIVE_PR`; direct efficacy `MISSING` |

Existing narrow design records under `docs/superpowers/specs/` remain useful
implementation history but are not substitutes for status-bearing ADRs. New
changes to trust authority, persistence, external producer contracts, or public
result semantics require an indexed ADR.
