### Added

- Added a dependency-free tenant-scoped retention policy core with explicit bounded product defaults, Boolean-safe optimistic concurrency, deterministic UTC cutoffs, and modular APIs for standalone AppGuardrail, organization services, and naruon integrations.
- Added hash-bound purge preview and non-secret receipt models that preserve policy revision, legal-hold revision, cutoffs, eligible and held counts, and stale-preview evidence without retaining deleted customer records; receipt creation now requires the current policy and legal-hold revisions and rejects execution timestamps before preview creation.
- Added a tenant-local tamper-evident audit event chain with canonical SHA-256 event hashes, duplicate-key rejection, expanded provider-token redaction, re-sanitized exports, mutation/reorder/internal-deletion detection, and optional trusted count or head-hash checkpoints for tail-truncation detection.
- Added explicit documentation that hash chaining is not physical immutability and that tail-deletion detection depends on an independently protected checkpoint.
- Added realistic cross-tenant, calendar-boundary, policy-conflict, legal-hold, stale-receipt, tampering, checkpoint, and secret-leak regression tests plus exact 100% statement coverage enforcement for the new production modules.
