# AppGuardrail UML and Runtime Views

**Status:** Accepted cross-cutting diagrams; active-PR boundaries labelled.  
**Last reviewed:** 2026-08-09

## Scan sequence

```mermaid
sequenceDiagram
    actor User
    participant CLI
    participant Discovery
    participant Builtin as Built-in detectors
    participant External as Optional external engines
    participant Findings
    participant Gate

    User->>CLI: scan target + options
    CLI->>Discovery: enumerate bounded supported files/config
    Discovery->>Builtin: normalized source/evidence
    Builtin-->>Findings: built-in findings
    opt installed/authorized external tools
        CLI->>External: bounded scan request
        External-->>Findings: engine-provenance findings
    end
    Findings->>Findings: normalize/deduplicate without erasing provenance
    Findings->>Gate: configured fail_on/exclusions
    Gate-->>User: findings + deploy outcome + evidence outputs
```

## Issue-obligation sequence — PR #911 active target

```mermaid
sequenceDiagram
    participant Inventory as Independent issue inventory
    participant Registry as Obligation registry
    participant Adapter as Detector adapter
    participant Detector as Actual executable detector
    participant Evidence as Closed/authenticated evidence

    Inventory->>Registry: retained issue/claim identities
    Registry->>Registry: map each to detector family/obligation
    Registry->>Adapter: detector obligation
    Evidence->>Adapter: evidence only; no expected answer
    Adapter->>Detector: execute real detector
    Detector-->>Adapter: finding / clean / inconclusive
    Adapter-->>Registry: obligation result + evidence digest
```

The registry cannot create `PASS` by declaring an issue `implemented` or by embedding the expected finding in fixture metadata.

## Safe remediation state machine

```mermaid
stateDiagram-v2
    [*] --> finding
    finding --> deterministic_fix_candidate: semantics-preserving transformer exists
    finding --> reviewable_guidance: behavior change required
    deterministic_fix_candidate --> preview
    preview --> applied: explicit --apply
    preview --> rejected
    applied --> rescan
    reviewable_guidance --> external_change
    external_change --> rescan
    rescan --> verified_fixed: detector no longer finds issue and regression passes
    rescan --> still_failing
    verified_fixed --> [*]
    rejected --> [*]
    still_failing --> finding
```

## Control-plane scan ingestion sequence

```mermaid
sequenceDiagram
    actor CI
    participant API as AppGuardrail control plane
    participant Auth as API-key role resolver
    participant DB as SQLite/current store
    participant Drift
    participant Webhook as Configured notifier

    CI->>API: POST scan + bearer key
    API->>Auth: authenticate and resolve organization/role
    Auth-->>API: tenant authority
    API->>API: validate bounded normalized findings
    API->>DB: persist scan under authenticated tenant
    DB-->>Drift: previous/current blocker evidence
    Drift-->>API: drift result
    opt new blockers + safe configured webhook
        API->>Webhook: bounded notification
    end
    API-->>CI: scan identity/outcome without secrets
```

## Detection maturity state

```mermaid
stateDiagram-v2
    [*] --> historical_issue
    historical_issue --> detector_obligation: claim is technically detectable
    historical_issue --> external_or_nondetectable: explicit rationale
    detector_obligation --> tests_red: positive/negative/inconclusive evidence
    tests_red --> executable_detector
    executable_detector --> exact_head_verified
    exact_head_verified --> protected_branch_detector
    protected_branch_detector --> monitored_regression
```

PR/issue text alone does not move a claim to `protected_branch_detector`.

## Deployment view

```mermaid
flowchart TB
    subgraph local[Local/CI]
        CLI[AppGuardrail CLI]
        TARGET[Target repository]
        OPTIONAL[Trivy / Semgrep / Bandit / Ruff / ZAP]
        TARGET --> CLI
        OPTIONAL --> CLI
    end

    subgraph control[Optional control plane]
        API[HTTP API]
        DB[(SQLite current / managed DB future)]
        DASH[Static org console]
        API --> DB
        DASH --> API
    end

    CLI -->|normalized scan push when configured| API
```

## Authority flow

```mermaid
flowchart LR
    TARGET[Untrusted target code]
    DET[Detector execution]
    FIND[Finding evidence]
    HUMAN[Builder/security owner]
    FIX[Fix path]
    CI[Re-verification]

    TARGET --> DET
    DET --> FIND
    FIND --> HUMAN
    HUMAN --> FIX
    FIX --> CI
    CI --> DET
```

A finding can trigger guidance but does not grant mutation authority. A clean rerun plus required repository gates is the verification loop.

## Maintenance rule

When a new scanner, persistent service, detection-obligation class, outbound executor, fix authority, or tenant boundary changes, update these diagrams with PRD/TRD/Architecture/ERD/Threat/Test/Operability/ADR/Traceability in the same reviewed change.