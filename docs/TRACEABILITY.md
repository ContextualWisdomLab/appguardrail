# AppGuardrail requirement traceability

This matrix prevents conversation-only decisions and separates requirement,
implementation, and evidence status.

## Status vocabulary

- `IMPLEMENTED_ON_PROTECTED_MAIN`: present on the exact protected `develop` tip.
- `ACTIVE_PR`: implemented or documented in an open PR only.
- `PARTIAL`: some required production boundaries are implemented.
- `MISSING`: no implementation/evidence meets the stated boundary.
- `ACCEPTED_TARGET_ARCHITECTURE`: accepted decision without complete protected
  implementation.
- `PLANNED`: prioritized but not accepted as implemented.
- `RESEARCH_ONLY`, `SUPERSEDED`, `DOWNSTREAM`, `OUT_OF_SCOPE`: non-production
  states that cannot be promoted to completion evidence.
- Documentation artifacts use `CURRENT_IN_ACTIVE_PR` when their content matches
  the reviewed PR state and `PARTIAL_IN_ACTIVE_PR` when the document is current
  but lacks an operationally necessary decision/runbook boundary. The JSON
  tokens are lowercase. Neither state means protected-main delivery.

## Requirements matrix

| Requirement | Product/decision | Implementation | Tests/evidence | Status |
|---|---|---|---|---|
| Retain every issue with no inventory exclusion. | PRD PR-06; ADR-0001 | registry and inventory audit | 414/414 identities and title/body digests | `ACTIVE_PR`; inventory only |
| Directly detect every underlying issue condition. | PRD PR-06/07; TRD TR-04 | trusted collector → native detector → independent oracle | 0/414 cause-bound issues; 0/417 validated direct claims | `MISSING` |
| A registry count is not detector efficacy. | TRD current boundary; ADR-0001/0004 | documentation guard | declared count/state inconsistencies fail; semantic efficacy remains manual/operational | `ACTIVE_PR` |
| Preserve mixed causes (#815 class). | PRD PR-07; TRD TR-06; ADR-0003 | generic log classifier only | synthetic multi-cause test; actual log format not replayed | `PARTIAL` |
| Distinguish aborted zero display + dependency outage (#813 class). | PRD PR-07 | generic log classifier only | current synthetic fixture is not authoritative clean evidence | `MISSING` direct replay |
| Classify expected dispatch rejection (#763 class). | PRD PR-07 | generic log classifier only | shell-source echo can false-positive; event/config detector absent | `MISSING` direct detector |
| External evidence has bounded payload provenance. | TRD TR-05; ADR-0002 | `WorkflowResultVerifier` | v2 HMAC/digest/producer/repository/run/head/source-artifact tamper tests; v1 retained as legacy classifier input | `ACTIVE_PR` classifier only |
| Stored and time-of-use SSRF are blocked. | PRD PR-05 | control plane + `pinned_https.py` | URL type, DNS/IP, redirect and delivery tests | `IMPLEMENTED_ON_PROTECTED_MAIN` plus active PR #910 hardening |
| Tenant data is isolated. | PRD PR-04; TRD TR-07 | authenticated control-plane queries | role and cross-tenant API tests | `IMPLEMENTED_ON_PROTECTED_MAIN` |
| Retention and audit evidence are bounded. | PRD PR-04/08; ADR-0005 | v2 schema/migration primitives | schema tests; purge/control-plane/API integration and live proof absent | `PARTIAL` |
| Local and MSA modes remain independent. | PRD PR-03 | CLI, JSON/SARIF/HTTP contracts | package, CLI and integration tests | `IMPLEMENTED_ON_PROTECTED_MAIN` |
| Canonical docs reconstruct architecture. | PRD PR-09 | architecture documentation graph | release documentation contract | `ACTIVE_PR` |
| Managed horizontally scaled persistence. | Architecture target | none | none | `PLANNED` |

## Documentation status matrix

| Family | Before PR #911 | PR #911 state |
|---|---|---|
| PRD | `MISSING` canonical product PRD | `CURRENT_IN_ACTIVE_PR` |
| TRD | `MISSING` canonical TRD | `CURRENT_IN_ACTIVE_PR` |
| Root architecture | `MISSING` | `CURRENT_IN_ACTIVE_PR` |
| ADR index/detail | `MISSING` canonical status-bearing ADR | five indexed status-bearing decisions, `CURRENT_IN_ACTIVE_PR` |
| UML views | `PARTIAL` scattered diagrams | canonical component/package/sequence/state/deployment/authority views, `CURRENT_IN_ACTIVE_PR` |
| ERD/evidence model | `MISSING` issue evidence model | protected-main legacy physical ERD, unintegrated v2 physical target, and conceptual issue-evidence target, `CURRENT_IN_ACTIVE_PR` |
| Security | `IMPLEMENTED_ON_PROTECTED_MAIN` root policy | retained and indexed as supporting documentation |
| Threat model | `PARTIAL` across narrow docs | canonical `CURRENT_IN_ACTIVE_PR` |
| Test strategy | `PARTIAL` in workflows/tests | canonical `CURRENT_IN_ACTIVE_PR` |
| Operability/recovery | `PARTIAL` | `PARTIAL_IN_ACTIVE_PR`; deployment owner, alert route, backup/restore, and approved RTO/RPO remain external or missing |
| Incident response | `MISSING` for issue detection | `PARTIAL_IN_ACTIVE_PR`; repository procedure exists, staffed on-call and managed evidence store remain missing |
| API/schema contracts | `PARTIAL` across README/narrow docs | indexed by Architecture/TRD, issue envelope `ACTIVE_PR` |
| Traceability | `MISSING` canonical | `CURRENT_IN_ACTIVE_PR`; efficacy remains 0/417 |
| Machine-readable documentation status | `MISSING` | topology/count/declared-status manifest and guard, `ACTIVE_PR`; semantic/remote proof excluded |
| AGENTS/CLAUDE/README/CHANGELOG | AGENTS stale, CLAUDE generic, README/CHANGELOG present | collector boundary, source-bound efficacy, status promotion, canonical links, and honest changelog reconciled, `ACTIVE_PR` |
| APA-7 references | `PARTIAL` | current primary standards in TRD, `ACTIVE_PR` |

## Evidence ownership

GitHub owns live issue/run/ref metadata; source producers own raw logs and
structured evidence generation; AppGuardrail owns schema, trust verification,
classification, and gate semantics; deployment operators own key distribution,
retention, regional/provider controls, and availability; consuming repositories
own remediation of their source findings.

## Current machine measurements

[`issue-detection-traceability.json`](issue-detection-traceability.json) is the
declared status record. The local guard checks its metadata, artifact topology,
local links, ADR index/detail structure, diagram declarations, registry counts,
and completion-count invariants. Human review owns prose correctness and
standards currency; exact-head GitHub evidence owns remote ancestry and
protected-main operation:

- registered inventory: 414/414 issue identities;
- registered claim rows: 417;
- unique `(classifier_family, claim_id)` semantics: 20;
- formally cause-bound issues: 0/414;
- independently validated direct-detector claims: 0/417; and
- protected-main operationally proven issues: 0/414.

The first three measurements are accounting/classifier structure. Only the
last three can advance issue-complete efficacy.

## Remaining execution queue

1. Add source repository/run/head, atomic cause, collector, detector, oracle,
   and trust-boundary fields to every claim.
2. Reconcile all 403 workflow observations from authoritative source evidence;
   group only after causal fingerprints are shown identical.
3. Add independent vulnerable, fixed, near-miss, partial, and unknown corpora
   outside the production registry.
4. Implement a direct vertical slice, starting with #763 event/config policy or
   #132 black-box secret-redaction, and prove mutation sensitivity.
5. Treat #815, #813, and #763 log parsing as bounded RCA hints until actual
   replay avoids echoed shell source and preserves unknown evidence.
6. Execute cause-bound adapters in the live audit, pass exact-head review and
   CI, merge under policy, then record protected-main operational proof.
