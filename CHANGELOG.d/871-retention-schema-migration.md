### Added

- Added a dependency-free, independently importable SQLite schema inspection and migration API for the embedded control plane.
- Added an atomic version-two migration that renames legacy one-word tables and indexes to descriptive multiword `snake_case` objects while preserving tenant, scan, webhook, role, label, and key-hash data.
- Added retention policy, legal hold, purge preview, purge receipt, audit event, and audit checkpoint persistence objects with append-only audit triggers.
- Added fail-closed validation for future, partial, mixed, malformed, orphaned, and active-transaction databases, plus explicit foreign-key verification before commit.
- Added an operator migration runbook and documented the separate application-integration phase required before production startup invokes the migration.
