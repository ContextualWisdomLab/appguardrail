# ADR-0005: Legacy and canonical-v2 persistence boundary

Status: Accepted

Date: 2026-08-09

Implementation: canonical v2 schema/migration primitives
`IMPLEMENTED_ON_PROTECTED_MAIN`; serving-path integration, purge APIs,
backup/restore operations, and live recovery proof `PARTIAL/MISSING`.

## Context

The protected-main control plane serves legacy `orgs`, `scans`, and `keys`
tables. A dependency-free migration module defines canonical multiword tables,
retention policies, legal holds, audit events/checkpoints, and purge
previews/receipts, but the primary `connect()`/HTTP path does not invoke the
migration.

## Decision

Keep the legacy and canonical-v2 persistence models explicit until an atomic
application integration is accepted:

- legacy tables remain the as-built serving schema;
- `controlplane_schema.py` owns inspected, forward-only, idempotent v2
  migration primitives;
- application startup, repository queries, owner APIs, purge execution,
  backup/restore, and rollback require a separate integrated change;
- schema availability is never evidence of serving-path adoption; and
- the physical ERD follows executable DDL, including zero-to-many purge
  receipts per preview while `preview_id` is not unique.

## Alternatives

1. Document v2 as the current runtime: rejected as false.
2. Add compatibility views and silently mix schemas: rejected because it hides
   migration ownership and failure modes.
3. Auto-migrate on every current connection before recovery proof: rejected as
   an unsafe expansion of the existing serving path.

## Consequences

The product carries two documented physical models during transition. Managed
service operation remains blocked on approved owners, RTO/RPO, encrypted
backup, isolated restore rehearsal, application integration, and purge/API
evidence.

## Acceptance

- Exact legacy and v2 schema fixtures and migration idempotency.
- Application queries and HTTP APIs use canonical objects atomically.
- Backup/restore and rollback rehearsals with measured loss/time.
- Retention/legal-hold/purge/audit behavior proven through the serving path.
- Protected-main operational verification after merge.
