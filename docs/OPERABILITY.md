# AppGuardrail operability and recovery

Local scanning and the optional control plane have separate failure domains.
A control-plane or provider outage must not prevent local deterministic scans;
it must prevent only the dependent evidence from being called complete.

## Service-level objectives

These are engineering targets, not historical performance claims:

- Local CLI: deterministic exit semantics and no network requirement for the
  native scan path.
- Control-plane API: 99.9% monthly availability target when deployed as a
  managed service; health must distinguish process liveness from datastore and
  outbound dependency readiness.
- Evidence integrity: 100% of accepted structured results bind schema,
  producer, run, head, source, digest, and attestation.
- Inventory reconciliation: every issue lifecycle event and scheduled audit
  either reconciles exactly or fails visibly; no inventory exclusions.
- Direct detector efficacy: 417/417 target; current active-PR evidence is 0/417.
- Per-issue cause binding: 414/414 target; current active-PR evidence is 0/414.
- Tenant boundary: zero tolerated cross-tenant read or mutation.

## Signals

Operators should record bounded counts and identifiers for request outcome,
scan duration/files/findings, drift blockers, migration version, purge preview
and receipt, audit-chain verification, detector family/outcome, provenance
failure class, inventory mismatch, outbound delivery class, and dependency
availability. Never log raw keys, raw authorized logs, or matched secrets.

## Runbook

### Issue inventory mismatch

1. Fetch all issue pages including closed issues and remove PR objects returned
   by the shared Issues API.
2. Compare issue-number sets and normalized requirement digests.
3. Review each changed requirement; update its claims, adapter contract,
   fixtures, tests, docs, and digest together.
4. Do not add waiver/exclusion/suppression fields.
5. Rerun focused efficacy/coverage and the live audit at the exact head.

### Unknown or failed provenance

1. Preserve the result as unknown and keep the gate blocked.
2. Verify envelope schema, exact producer, repository/run/head/source identity,
   payload digest, evidence reference, key strength, and HMAC.
3. If capability exposure is suspected, rotate it at the source producer and
   invalidate affected evidence.
4. Reissue evidence for the unchanged exact source head; never copy predecessor
   evidence forward.

### Control-plane incident

1. Stop write traffic and copy the application-owned database and deployment
   configuration to controlled incident storage.
2. Verify schema version and audit chain before repair.
3. Restore into an isolated process; run inspection/migration dry-runs and
   tenant-boundary acceptance.
4. Resume read traffic, then bounded writes; preserve local CLI availability.

### Outbound delivery incident

Disable only the affected destination, preserve bounded failure evidence,
re-resolve and revalidate the full destination/redirect chain, and retry only
idempotent notifications. Never broaden private-address access as a remedy.

## Recovery

- Code rollback: revert the exact change commit and rerun package plus
  protected-head tests.
- Registry rollback: revert code, registry, tests, and docs atomically; never
  retain a registry whose adapter code is absent.
- Database rollback: restore the pre-migration backup only after version and
  audit verification; forward-fix is preferred once production writes exist.
- Credential recovery: rotate API/HMAC/release credentials, revoke old
  capability, and regenerate exact-head evidence.

## Release and rollback evidence

`docs/release-automation.md`, `CHANGELOG.md`, changelog fragments, package
manifests, exact-head Actions, SBOM/provenance artifacts, and migration records
form the release evidence set. Release is blocked until rollback and protected
main verification are both observable.

## Work-conserving execution queue

One blocked source log, provider, review, or branch blocks only that lane. Move
to another cause binding, collector, independent corpus, detector, test,
documentation repair, or protected-main probe. Current priority is the
machine-readable queue in `docs/TRACEABILITY.md`; inventory registration and a
documentation commit are intermediate states, not run completion.
