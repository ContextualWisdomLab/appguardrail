# Retention and Audit Buyer Diligence

**Status:** Active PR; not protected-branch shipped truth until merged and reverified.  
**Scope:** Non-secret, tenant-scoped acquisition/readiness evidence.  
**Related issue:** #871.

## Buyer decision this evidence supports

A buyer or security reviewer needs to distinguish a configured retention policy from evidence that the policy and audit trail were actually observed at a specific point in time. AppGuardrail therefore exposes a deliberately small posture object and a buyer-report section that answer four questions without exporting customer records:

1. Which retention-policy revision and category durations were observed?
2. How many legal holds were active at verification time?
3. Was the append-only audit chain explicitly verified, and what event count/head hash was observed?
4. Is there a completed purge receipt that can be correlated to policy and legal-hold revisions?

A `verified` posture is evidence of the supplied snapshot only. It is **not** a certification, continuous-compliance claim, proof that deletion occurred for every eligible record, or proof that the current tenant state still matches the snapshot. Buyer copy always directs the reviewer to re-verify current tenant state before acquisition reliance.

## Security and privacy boundary

`RetentionAuditPosture.to_dict()` intentionally omits tenant IDs, actor IDs, request IDs, authorization headers, raw audit summaries, customer payloads, and deletion-record contents. The accepted purge evidence is limited to receipt ID, execution timestamp, policy revision, and legal-hold revision.

The aggregation boundary fails closed for malformed timestamps, hashes, counters, incomplete retention categories, retention values outside configured bounds, impossible verified-chain shapes, and cross-tenant purge receipts. `unverified` and `failed` audit-chain states produce `incomplete` diligence evidence rather than being promoted to verified evidence.

The buyer report keeps posture input explicit through `render_buyer_retention_diligence_report(...)`; it does not silently attach tenant-specific state to the generic `ReportContext`. When posture is omitted, the report says `Evidence status: Not supplied` and tells the reviewer what evidence to supply next.

## Integration contract

```python
from appguardrail_core.reports import ReportContext
from appguardrail_core.retention_diligence import build_retention_audit_posture
from appguardrail_core.retention_diligence_report import (
    render_buyer_retention_diligence_report,
)

posture = build_retention_audit_posture(
    policy,
    legal_hold_count=legal_hold_count,
    audit_event_count=audit_event_count,
    audit_chain_status=audit_chain_status,
    audit_head_hash=audit_head_hash,
    verified_at=verified_at,
    last_purge_receipt=last_purge_receipt,
)

report = render_buyer_retention_diligence_report(
    findings,
    ReportContext(repository=repository, commit=commit),
    retention_audit_posture=posture,
)
```

The caller remains responsible for obtaining tenant-scoped domain objects from an authorized control-plane boundary. This slice does not add retention-policy mutation, purge execution, legal-hold mutation, or a new authorization path.

## Verification evidence

The branch's deterministic `Retention Audit Coverage` workflow measures exact unrounded statement coverage for:

- `appguardrail_core/audit_events.py`;
- `appguardrail_core/retention_policy.py`;
- `appguardrail_core/retention_diligence.py`;
- `appguardrail_core/retention_diligence_report.py`.

Focused tests cover verified/incomplete/missing evidence, cross-tenant rejection, malformed public construction, retention bounds, purge metadata, sensitive-value exclusion, buyer next-action copy, and report composition. Promotion to shipped truth still requires the unchanged exact PR head to satisfy all live protected-branch checks and independent-review policy.

## Out of scope for this slice

- claiming CSAP, SOC 2, ISO, or other certification;
- interpreting a collector/CI failure as proof of a source vulnerability;
- exposing tenant identifiers or raw audit-event content in buyer output;
- implementing control-plane retention CRUD, legal-hold CRUD, or purge execution;
- replacing live due-diligence verification with a historical snapshot.
