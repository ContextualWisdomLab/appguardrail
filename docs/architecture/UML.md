# AppGuardrail UML views

The diagrams are architecture-as-code. Components are labeled
`IMPLEMENTED`, `ACTIVE_PR`, or `MISSING`; target sequences do not claim a
current call path.

## Component diagram

```mermaid
flowchart TB
  subgraph Product[AppGuardrail product]
    CLI[CLI and project traversal]
    Native[Native rule engine]
    External[External-engine adapters]
    Normalize[Finding normalization]
    Output[SARIF / JSON / reports / SBOM]
    Control[Authenticated control plane]
    Store[(SQLite store)]
    Delivery[DNS-pinned HTTPS delivery]
    Registry[Issue registry - ACTIVE_PR]
    Classifier[Evidence classifiers - ACTIVE_PR]
    Detector[Cause-bound direct detectors - MISSING]
    Audit[Inventory audit - ACTIVE_PR]
    Efficacy[Live efficacy audit - MISSING]
  end
  CLI --> Native
  CLI --> External
  Native --> Normalize
  External --> Normalize
  Normalize --> Output
  Normalize --> Control
  Control --> Store
  Control --> Delivery
  Registry --> Classifier
  Classifier --> Detector
  Detector --> Output
  Audit --> Registry
  Efficacy --> Detector
```

## Package diagram

```mermaid
flowchart TD
  scanner_cli[scanner.cli] --> scanner_rules[scanner.rules]
  scanner_cli --> findings[appguardrail_core.findings]
  findings --> sarif[appguardrail_core.sarif]
  findings --> reports[appguardrail_core.reports]
  scanner_cli --> controlplane[appguardrail_core.controlplane]
  controlplane --> schema[appguardrail_core.controlplane_schema]
  controlplane --> pinned[appguardrail_core.pinned_https]
  issue_detection[appguardrail_core.issue_detection] --> registry[issue_detection_registry.json]
  issue_detection --> findings
```

## Sequence diagram

This is the accepted target sequence. PR #911 stops at generic classifier
execution because claim-specific collectors, direct detectors, and independent
oracles are not yet bound.

```mermaid
sequenceDiagram
  participant P as Trusted producer
  participant A as AppGuardrail adapter
  participant R as Issue registry
  participant O as Operator / CI
  P->>P: Compute structured result and payload digest
  P->>A: Envelope + exact run/head/source identity + HMAC
  A->>A: Verify schema, producer, HMAC, digest, run and head
  A->>R: Resolve claim and closed detector family
  R-->>A: Evidence schema, obligations, adapter identity
  A->>A: Execute production adapter for every cause
  A-->>O: Assessments + gate_satisfied + bounded provenance hash
  Note over A,O: Missing or malformed authority returns unknown, never clean
```

## State diagram

```mermaid
stateDiagram-v2
  [*] --> EvidenceReceived
  EvidenceReceived --> Unknown: missing / malformed / extra / unauthenticated
  EvidenceReceived --> Classified: closed schema and authority verified
  Classified --> ConfirmedFinding: source-backed security finding
  Classified --> Clean: complete negative evidence
  Classified --> ControlEffective: expected control blocked unsafe action
  Classified --> DependencyFailure: provider or infrastructure unavailable
  Classified --> ReportingFailure: result publication failed
  Unknown --> GateBlocked
  ConfirmedFinding --> GateBlocked
  DependencyFailure --> GateBlocked
  ReportingFailure --> GateBlocked
  Clean --> GateSatisfied
  ControlEffective --> GateSatisfied
```

## Deployment diagram

```mermaid
flowchart TD
  subgraph Workstation_or_CI[Workstation or CI runner]
    Wheel[AppGuardrail wheel]
    Project[Target repository]
    Evidence[Authorized evidence files]
  end
  subgraph Optional_service[Optional AppGuardrail service]
    API[Python HTTP process]
    DB[(Application-owned SQLite)]
    UI[Static console]
  end
  GitHub[GitHub REST / Actions] -->|read-only inventory and metadata| Wheel
  Project --> Wheel
  Evidence --> Wheel
  Wheel -->|authenticated JSON| API
  API --> DB
  API --> UI
  API -->|public HTTPS, DNS/IP pinned| Hook[Approved webhook]
```

## Authority diagram

```mermaid
flowchart TD
  Issue[Issue number/title/body] -->|defines requirement only| Claim[Issue claim]
  Registry[Reviewed registry contract] --> Claim
  Producer[Trusted producer identity] --> Envelope[Signed evidence envelope]
  Run[Exact repo/run/head/source] --> Envelope
  Envelope --> Adapter[Closed production adapter]
  Claim --> Adapter
  Adapter --> Assessment[Runtime assessment]
  Assessment --> Gate[Gate decision]
  Collector[Actions failure collector] -. telemetry only .-> Adapter
  Prose[Issue prose / labels] -. cannot assert outcome .-> Assessment
```
