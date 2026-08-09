# AppGuardrail requirement traceability

This matrix prevents conversation-only decisions and separates requirement,
implementation, and evidence status.

## Status vocabulary

- `IMPLEMENTED_ON_PROTECTED_MAIN`: present on the exact protected `develop` tip.
- `ACTIVE_PR`: implemented or documented in an open PR only.
- `PARTIAL`: some required production boundaries are implemented.
- `ACCEPTED_TARGET_ARCHITECTURE`: accepted decision without complete protected
  implementation.
- `PLANNED`: prioritized but not accepted as implemented.
- `RESEARCH_ONLY`, `SUPERSEDED`, `DOWNSTREAM`, `OUT_OF_SCOPE`: non-production
  states that cannot be promoted to completion evidence.

## Requirements matrix

| Requirement | Product/decision | Implementation | Tests/evidence | Status |
|---|---|---|---|---|
| Every issue is detectable with no exclusions. | PRD PR-06; ADR-0001 | `issue_detection.py`, registry | inventory, digest, adapter, obligation, adversarial tests | `ACTIVE_PR` |
| A registry count is not detector efficacy. | TRD TR-04; ADR-0001 | callable adapter map | positive/negative/unknown and mutation-sensitive matrix | `ACTIVE_PR` |
| Preserve mixed causes (#815 class). | PRD PR-07; TRD TR-06 | assessment aggregation | multi-cause tests | `ACTIVE_PR` |
| Distinguish clean + dependency outage (#813 class). | PRD PR-07 | workflow cause and structured result adapters | zero-finding/rate-limit/cancellation fixtures | `ACTIVE_PR` |
| Classify expected dispatch rejection (#763 class). | PRD PR-07 | pull-request metadata/control adapters | authorized/unauthorized/malformed fixtures | `ACTIVE_PR` |
| External evidence is provenance-bound. | TRD TR-05; ADR-0001 | `WorkflowResultVerifier` | HMAC/digest/producer/run/head tamper tests | `ACTIVE_PR` |
| Stored and time-of-use SSRF are blocked. | PRD PR-05 | control plane + `pinned_https.py` | URL type, DNS/IP, redirect and delivery tests | `IMPLEMENTED_ON_PROTECTED_MAIN` plus active PR #910 hardening |
| Tenant data is isolated. | PRD PR-04; TRD TR-07 | authenticated control-plane queries | role and cross-tenant API tests | `IMPLEMENTED_ON_PROTECTED_MAIN` |
| Retention and audit evidence are bounded. | PRD PR-04/08 | retention policy, audit events, schema migration | policy/preview/receipt/chain/migration tests | `IMPLEMENTED_ON_PROTECTED_MAIN` |
| Local and MSA modes remain independent. | PRD PR-03 | CLI, JSON/SARIF/HTTP contracts | package, CLI and integration tests | `IMPLEMENTED_ON_PROTECTED_MAIN` |
| Canonical docs reconstruct architecture. | PRD PR-09 | architecture documentation graph | release documentation contract | `ACTIVE_PR` |
| Managed horizontally scaled persistence. | Architecture target | none | none | `PLANNED` |

## Documentation fitness matrix

| Family | Before PR #911 | PR #911 state |
|---|---|---|
| PRD | `MISSING` canonical product PRD | `PRESENT_CURRENT`, `ACTIVE_PR` |
| TRD | `MISSING` canonical TRD | `PRESENT_CURRENT`, `ACTIVE_PR` |
| Root architecture | `MISSING` | `PRESENT_CURRENT`, `ACTIVE_PR` |
| ADR index/detail | `MISSING` canonical status-bearing ADR | `PRESENT_CURRENT`, `ACTIVE_PR` |
| UML views | `PARTIAL` scattered diagrams | canonical component/package/sequence/state/deployment/authority views, `ACTIVE_PR` |
| ERD/evidence model | `MISSING` issue evidence model | conceptual, explicitly non-persistent, `ACTIVE_PR` |
| Security | `PRESENT_CURRENT` root policy | retained |
| Threat model | `PARTIAL` across narrow docs | canonical `PRESENT_CURRENT`, `ACTIVE_PR` |
| Test strategy | `PARTIAL` in workflows/tests | canonical `PRESENT_CURRENT`, `ACTIVE_PR` |
| Operability/recovery | `PARTIAL` | canonical `PRESENT_CURRENT`, `ACTIVE_PR` |
| API/schema contracts | `PARTIAL` across README/narrow docs | indexed by Architecture/TRD, issue envelope `ACTIVE_PR` |
| Traceability | `MISSING` canonical | `PRESENT_CURRENT`, `ACTIVE_PR` |
| AGENTS/CLAUDE/README/CHANGELOG | `PRESENT_CURRENT` with missing canonical map | linked/extended in PR #911 |
| APA-7 references | `PARTIAL` | current primary standards in TRD, `ACTIVE_PR` |

## Evidence ownership

GitHub owns live issue/run/ref metadata; source producers own raw logs and
structured evidence generation; AppGuardrail owns schema, trust verification,
classification, and gate semantics; deployment operators own key distribution,
retention, regional/provider controls, and availability; consuming repositories
own remediation of their source findings.
