# AppGuardrail conceptual evidence model

This model explains evidence authority and traceability. It is not a claim that
these entities are database tables. The protected-main control plane persists
its current SQLite `orgs`, `keys`, and `scans` schema; the issue-derived model
below is immutable registry plus runtime data in PR #911.

## Conceptual ERD

```mermaid
erDiagram
  ISSUE_REQUIREMENT ||--|{ DETECTION_CLAIM : retains
  DETECTOR_FAMILY ||--|{ DETECTION_CLAIM : implements
  DETECTOR_FAMILY ||--|{ DETECTION_OBLIGATION : specifies
  DETECTOR_FAMILY ||--|| EVIDENCE_SCHEMA : accepts
  DETECTOR_FAMILY ||--|| PRODUCTION_ADAPTER : executes
  WORKFLOW_EXECUTION ||--o{ EVIDENCE_ENVELOPE : produces
  SOURCE_REVISION ||--o{ WORKFLOW_EXECUTION : checks
  EVIDENCE_ENVELOPE ||--|| PROVENANCE_ATTESTATION : authenticates
  DETECTION_CLAIM ||--o{ DETECTION_ASSESSMENT : yields
  EVIDENCE_ENVELOPE ||--o{ DETECTION_ASSESSMENT : supports
  DETECTION_ASSESSMENT ||--|| GATE_DECISION : contributes

  ISSUE_REQUIREMENT {
    int issue_number PK
    string requirement_sha256
    datetime issue_updated_at
    boolean retained_detection_requirement
  }
  DETECTION_CLAIM {
    string claim_id PK
    int issue_number FK
    string detector_family_id FK
    string condition_id
  }
  DETECTOR_FAMILY {
    string detector_family_id PK
    string adapter_id
    string adapter_ref
    boolean no_exclusions
  }
  DETECTION_OBLIGATION {
    string obligation_id PK
    string detector_family_id FK
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

## Persistence boundary

- Persisted today: tenant organizations, role-scoped API-key hashes, scan
  records, findings JSON, drift metadata, webhook configuration, and schema
  versioning in the control-plane SQLite store.
- Packaged configuration in `ACTIVE_PR`: issue requirements, claims, detector
  families, obligations, evidence schemas, fixtures, adapter references, and
  requirement digests in `issue_detection_registry.json`.
- Runtime only: source logs, HMAC capability, evidence envelopes, adapter
  assessments, and gate aggregation unless an authorized consumer stores them.
- Never persisted by this contract: raw secrets, raw authorized source logs, or
  attestation keys.

The conceptual entity names use descriptive multiword snake_case. Existing
one-word SQLite table names are legacy protected-main schema and require a
separate migration ADR; this PR does not silently rename persisted objects.

## Invariants

1. Every `issue_requirement` has at least one `detection_claim`.
2. Every claim resolves to one callable `production_adapter` through a closed
   `detector_family`.
3. Every obligation has positive, negative, and unknown executions.
4. Runtime authority comes from evidence schema and provenance, never from the
   issue requirement.
5. `source_revision`, `workflow_execution`, and `evidence_envelope` identities
   are distinct and cannot substitute for each other.
6. A `gate_decision` cannot be satisfied by unknown, dependency failure,
   reporting failure, or confirmed finding.
