# AppGuardrail evidence and persistence models

This model explains evidence authority and traceability. It is not a claim that
these entities are database tables. The protected-main control plane persists
its current SQLite `orgs`, `keys`, and `scans` schema. The issue-derived model
below is accepted target architecture: PR #911 currently persists only issue
identity, generic claim/family mapping, contracts, fixtures, and digests. It
does not yet persist claim-specific cause, collector, oracle, or evidence links.

## Conceptual ERD

```mermaid
erDiagram
  ISSUE_REQUIREMENT ||--|{ DETECTION_CLAIM : retains
  DETECTION_CLAIM ||--|| ATOMIC_CAUSE : binds
  DETECTOR_FAMILY ||--|{ DETECTION_CLAIM : implements
  DETECTOR_FAMILY ||--|{ DETECTION_OBLIGATION : specifies
  DETECTION_CLAIM ||--|{ DETECTION_OBLIGATION : selects
  DETECTOR_FAMILY ||--|| EVIDENCE_SCHEMA : accepts
  DETECTOR_FAMILY ||--|| PRODUCTION_ADAPTER : executes
  DETECTION_CLAIM ||--|| TRUSTED_COLLECTOR : observes
  DETECTION_CLAIM ||--|{ ORACLE_FIXTURE : validates
  WORKFLOW_EXECUTION ||--o{ EVIDENCE_ENVELOPE : produces
  SOURCE_REVISION ||--o{ WORKFLOW_EXECUTION : checks
  EVIDENCE_ENVELOPE ||--|| PROVENANCE_ATTESTATION : authenticates
  DETECTION_CLAIM ||--o{ DETECTION_ASSESSMENT : yields
  EVIDENCE_ENVELOPE ||--o{ DETECTION_ASSESSMENT : supports
  PRODUCTION_ADAPTER ||--o{ DETECTION_ASSESSMENT : computes
  ORACLE_FIXTURE ||--o{ DETECTION_ASSESSMENT : expects
  DETECTION_ASSESSMENT ||--|| GATE_DECISION : contributes

  ISSUE_REQUIREMENT {
    int issue_number PK
    string requirement_sha256
    datetime issue_updated_at
    boolean retained_detection_requirement
  }
  DETECTION_CLAIM {
    int issue_number PK, FK
    string claim_id PK
    string detector_family_id FK
    string condition_id
  }
  ATOMIC_CAUSE {
    string condition_id PK
    string cause_class
    string causal_chain
    string trust_boundary
  }
  DETECTOR_FAMILY {
    string detector_family_id PK
    string adapter_id
    string adapter_ref
    boolean no_exclusions
  }
  DETECTION_OBLIGATION {
    string detector_family_id PK, FK
    string obligation_id PK
    string condition
    string required_evidence_fields
  }
  EVIDENCE_SCHEMA {
    string evidence_schema_id PK
    string allowed_evidence_fields
    string required_evidence_fields
  }
  PRODUCTION_ADAPTER {
    string adapter_id PK
    string implementation_ref
  }
  TRUSTED_COLLECTOR {
    string collector_id PK
    string source_repository
    string source_contract
    string trust_boundary
  }
  ORACLE_FIXTURE {
    string oracle_fixture_id PK
    int issue_number FK
    string claim_id FK
    string scenario_kind
    string fixture_reference
    string expected_reason_code
  }
  WORKFLOW_EXECUTION {
    string workflow_run_id PK
    string repository_name
    string producer_id
    string head_sha FK
  }
  SOURCE_REVISION {
    string head_sha PK
    string repository_name
  }
  EVIDENCE_ENVELOPE {
    string evidence_reference PK
    string workflow_run_id FK
    string payload_sha256
    string envelope_schema
  }
  PROVENANCE_ATTESTATION {
    string evidence_reference FK
    string attestation_algorithm
    string producer_id
  }
  DETECTION_ASSESSMENT {
    string assessment_id PK
    int issue_number FK
    string claim_id FK
    string outcome_state
    boolean gate_satisfied
    string evidence_hash
  }
  GATE_DECISION {
    string gate_decision_id PK
    string decision_state
    datetime evaluated_at
  }
```

`claim_id` repeats across issues: 417 rows currently contain only 20 unique
claim IDs. The target key is therefore the composite `(issue_number, claim_id)`
until a globally unique `cause_id` is introduced.

`obligation_id` also repeats across families: the registry has 140 obligation
rows but only 104 distinct bare IDs. Its target key is the composite
`(detector_family_id, obligation_id)`, which is unique for all 140 rows.
`ORACLE_FIXTURE` and `DETECTION_ASSESSMENT` use the composite foreign key
`(issue_number, claim_id)` to `DETECTION_CLAIM`; neither column is a valid
standalone claim reference.

## Protected-main legacy physical ERD

`appguardrail_core.controlplane.connect()` currently creates and uses this
legacy runtime schema on protected `develop`:

```mermaid
erDiagram
  ORGS ||--o{ SCANS : owns
  ORGS ||--o{ KEYS : authorizes

  ORGS {
    int id PK
    string name
    string api_key_hash UK
    string webhook_url
    datetime created_at
  }
  SCANS {
    int id PK
    int org_id FK
    string repo
    string commit_sha
    int deploy_blocking
    string findings
    datetime created_at
  }
  KEYS {
    int id PK
    int org_id FK
    string key_hash UK
    string role
    string label
    datetime created_at
  }
```

## Canonical v2 migration schema

`appguardrail_core.controlplane_schema` defines and tests this migration target,
but the primary control-plane `connect()`/HTTP path does not yet invoke it.
Schema availability is implemented; application integration, purge execution,
and protected-main operational proof remain `PARTIAL`.

```mermaid
erDiagram
  TENANT_ORGANIZATIONS ||--o{ SECURITY_SCANS : owns
  TENANT_ORGANIZATIONS ||--o{ ACCESS_KEYS : authorizes
  TENANT_ORGANIZATIONS ||--o| RETENTION_POLICIES : governs
  TENANT_ORGANIZATIONS ||--o{ LEGAL_HOLDS : retains
  TENANT_ORGANIZATIONS ||--o{ AUDIT_EVENTS : records
  TENANT_ORGANIZATIONS ||--o{ AUDIT_CHAIN_CHECKPOINTS : checkpoints
  TENANT_ORGANIZATIONS ||--o{ PURGE_PREVIEWS : previews
  TENANT_ORGANIZATIONS ||--o{ PURGE_RECEIPTS : receipts
  PURGE_PREVIEWS ||--o{ PURGE_RECEIPTS : authorizes

  TENANT_ORGANIZATIONS {
    int id PK
    string name
    string api_key_hash UK
    string webhook_url
  }
  SECURITY_SCANS {
    int id PK
    int org_id FK
    string repo
    string commit_sha
    string findings
  }
  ACCESS_KEYS {
    int id PK
    int org_id FK
    string key_hash UK
    string role
  }
  RETENTION_POLICIES {
    int tenant_id PK, FK
    int revision
    int scan_history_days
    int audit_event_days
  }
  LEGAL_HOLDS {
    string legal_hold_id PK
    int tenant_id FK
    string hold_state
    string subject_id
  }
  AUDIT_EVENTS {
    string audit_event_id PK
    int tenant_id FK
    int sequence_number UK
    string event_hash UK
  }
  AUDIT_CHAIN_CHECKPOINTS {
    string checkpoint_id PK
    int tenant_id FK
    int through_sequence_number UK
    string event_hash
  }
  PURGE_PREVIEWS {
    string preview_id PK
    int tenant_id FK
    int policy_revision
    string preview_hash UK
  }
  PURGE_RECEIPTS {
    string receipt_id PK
    int tenant_id FK
    string preview_id FK
    string receipt_hash UK
  }
```

The current DDL does not declare `purge_receipts.preview_id` unique, so one
preview can reference zero or many receipts. If the product chooses a strict
one-preview/one-receipt idempotency invariant, that requires a schema migration
and tests; the ERD must not claim it before the constraint exists.

## Persistence boundary

- Persisted by the current runtime: legacy `orgs`, `scans`, and `keys`, including
  role-scoped API-key hashes, findings JSON, drift, and webhook configuration.
- Defined by the v2 migration module but not integrated into the main runtime:
  canonical names, retention policy, legal hold, append-only audit,
  checkpoints, purge previews/receipts, and schema versioning.
- Packaged configuration in `ACTIVE_PR`: issue requirements, claims, detector
  families, obligations, evidence schemas, fixtures, adapter references, and
  requirement digests in `issue_detection_registry.json`.
- Runtime only: source logs, HMAC capability, evidence envelopes, adapter
  assessments, and gate aggregation unless an authorized consumer stores them.
- Never persisted by this contract: raw secrets, raw authorized source logs, or
  attestation keys.

The conceptual entity names use descriptive multiword snake_case. Existing
one-word SQLite table names remain the protected-main runtime schema; the v2
migration is not evidence that the serving path has adopted them.

## Invariants

These are release-target invariants, not a claim about the active PR:

1. Every `issue_requirement` has at least one cause-bound `detection_claim`.
2. Every claim resolves to a trusted collector, native `production_adapter`,
   and independent oracle through a closed `detector_family`.
3. Every obligation has independent vulnerable, fixed, near-miss, malformed,
   partial, and unknown executions outside the production registry.
4. Runtime authority comes from evidence schema and provenance, never from the
   issue requirement.
5. `source_revision`, `workflow_execution`, and `evidence_envelope` identities
   are distinct and cannot substitute for each other.
6. A `gate_decision` cannot be satisfied by unknown, dependency failure,
   reporting failure, or confirmed finding.

Current gap: 0/414 issues meet the first cause-bound invariant and 0/417 claims
have independently validated direct-detector efficacy.
