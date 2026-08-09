### Added

- Added an executable no-exclusions contract for all 414 retained AppGuardrail
  issues and 417 independent claims, with 17 callable detector families,
  closed evidence-field and required-evidence-field contracts, and
  machine-readable `obligations[]` proven by positive, negative, and unknown
  executions of each full condition. Unsupported, extra, or missing evidence
  is unknown and fail-closed. The contract also includes provenance-bound
  workflow-result classification authenticated by an externally provisioned
  HMAC capability, recomputed payload and issue-requirement digests, an
  installed audit CLI, and read-only exact-coverage and live-inventory workflows.
- Added a canonical PRD, TRD, root architecture, status-bearing ADR, UML views,
  conceptual evidence model, threat model, test strategy, operability runbook,
  and requirement-to-code/test/evidence traceability matrix. These documents
  distinguish protected-main behavior, the active PR, accepted targets, and
  planned work and are enforced by a release-contract test.
