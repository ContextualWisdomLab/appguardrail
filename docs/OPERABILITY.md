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

The active-PR envelope does not meet the evidence-integrity target: it binds
producer, run, head, evidence reference, payload digest, and HMAC, but not the
repository or source artifact.

## Signals

Operators should record bounded counts and identifiers for request outcome,
scan duration/files/findings, drift blockers, migration version, purge preview
and receipt, audit-chain verification, detector family/outcome, provenance
failure class, inventory mismatch, outbound delivery class, and dependency
availability. Never log raw keys, raw authorized logs, or matched secrets.

## Ownership and escalation

No named on-call roster or managed alert route is stored in this repository.
That operational binding is a managed-service GA prerequisite, not an implied
property of the package.

| Surface | Primary owner role | Escalation path |
|---|---|---|
| Package, registry, canonical docs, and repository CI | AppGuardrail maintainer for the exact changed paths | Block the PR/release and use its exact-head Actions and review thread. Security-sensitive material follows `SECURITY.md`, never a public issue. |
| Optional deployed control plane and SQLite data | The organization that deploys the service | Its deployment runbook and incident commander; this repository cannot name or page that external owner. |
| Source evidence producer, workflow, or external engine | The owning repository/service maintainer | Mark only that evidence lane unknown/dependency-failed and keep the AppGuardrail direct-efficacy gate blocked. |
| Release signing, package publication, and provenance | Repository release maintainer with environment approval | Stop publication, revoke/rotate affected credentials, and open a private security advisory when compromise is possible. |

Alert sources implemented in the repository are GitHub Actions status, the
scheduled/lifecycle issue inventory audit, explicit CLI exit status, and the
control-plane health endpoint. Pager delivery, datastore-ready alerting,
managed SLO burn alerts, and source-producer alert routing are `PLANNED` and
must not be represented as operational. Any inventory mismatch, invalid
provenance, cross-tenant access, audit-chain break, or release-attestation
failure is a zero-tolerance release blocker rather than a sampled warning.

## Operator commands

Run commands from a clean checkout of the exact candidate SHA. The supported
repository checks are:

```bash
python -m pytest -q
python -m scripts.ci.verify_module_coverage \
  --module appguardrail_core/issue_detection.py \
  --test tests/test_issue_detection.py \
  --test tests/test_issue_detection_release_contract.py
python -m scripts.ci.verify_module_coverage \
  --module appguardrail_core/issue_detection_docs.py \
  --test tests/test_issue_detection_documentation.py
```

The live inventory command requires an authorized GitHub CLI session and a
bounded temporary file; it is read-only:

```bash
appguardrail_issues_file="$(mktemp)"
gh api --paginate --slurp \
  "/repos/ContextualWisdomLab/appguardrail/issues?state=all&per_page=100" \
  > "${appguardrail_issues_file}"
python -m appguardrail_core.issue_detection audit-registry \
  --issues-file "${appguardrail_issues_file}"
```

There is no supported source-acquisition/live-efficacy command yet. The
`classify-workflow` command classifies already-authorized caller input and is
not a substitute for one.

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
2. Verify only the fields the active envelope actually binds: schema, producer,
   run, head, payload digest, evidence reference, key strength, and HMAC. It
   does not bind repository or source-artifact identity; preserve those checks
   as `MISSING` and do not promote the evidence to direct efficacy.
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

## Recovery-objective status

| Surface | RTO/RPO status | Evidence required before promotion |
|---|---|---|
| Local CLI and packaged rules | No service RTO/RPO: reinstall the exact signed package/commit; project source remains owner-controlled. | Package installation and exact-source scan probe. |
| Registry and canonical documentation | Git is the recovery source; restore one reviewed atomic code/registry/test/docs commit. No runtime RPO is claimed. | Revert rehearsal plus exact-head and protected-main audits. |
| Optional control plane and SQLite | Approved production RTO/RPO is not defined; backup automation, restore command, and rehearsal are `MISSING` managed-service blockers. | Deployment-specific ADR/runbook, encrypted backup evidence, isolated restore, schema/audit/tenant checks, and measured recovery time/data loss. |
| External evidence and HMAC capability | Source-owner recovery objectives are outside this repository and currently unbound. | Producer-specific rotation/reissue procedure and source-bound replay proof. |

The 99.9% availability line above is a design target, not an approved recovery
commitment. A managed-service release is blocked until accountable owners,
alert routes, RTO/RPO, backup/restore automation, and rehearsal evidence are
bound to the deployed environment.

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
