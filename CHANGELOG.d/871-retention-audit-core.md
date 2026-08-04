### Added

- Added a dependency-free tenant-scoped retention policy core with explicit bounded product defaults, optimistic concurrency, deterministic UTC cutoffs, and modular APIs for standalone AppGuardrail, organization services, and naruon integrations.
- Added hash-bound purge preview and non-secret receipt models that preserve policy revision, legal-hold revision, cutoffs, eligible and held counts, and stale-preview evidence without retaining deleted customer records.
- Added a tenant-local tamper-evident audit event chain with canonical SHA-256 event hashes, secret and raw-evidence redaction, mutation/reorder/deletion detection, and explicit documentation that hash chaining is not physical immutability.
- Added realistic cross-tenant, calendar-boundary, policy-conflict, legal-hold, tampering, and secret-leak regression tests plus exact 100% statement coverage enforcement for the new production modules.
