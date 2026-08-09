# AppGuardrail technical requirements document

## Scope and status

This TRD covers the protected-main AppGuardrail product and the issue-complete
detection contract in PR #911. The latter is `ACTIVE_PR`, not yet production.

## Technical requirements

| ID | Requirement | Verification boundary |
|---|---|---|
| TR-01 | Python 3.11+ dependency-free production runtime. | Build wheel/sdist and run supported Python matrices. |
| TR-02 | Closed normalized finding and evidence schemas. | Reject unknown, missing, malformed, non-finite, stale, and extra authoritative fields. |
| TR-03 | Complete open-and-closed issue pagination and requirement digest reconciliation. | Compare the live GitHub inventory with the packaged registry on issue lifecycle events and schedule. |
| TR-04 | Each claim binds a callable production adapter and realistic positive/negative/unknown fixtures. | Execute the adapter; registry presence alone is insufficient. |
| TR-05 | External results bind exact producer, repository/run/head identity, evidence reference, payload digest, and HMAC capability. | Tamper, wrong-producer, wrong-run, wrong-head, replay, weak-key, and missing-key tests fail closed. |
| TR-06 | Multi-cause results preserve independent assessments. | One observation can return both source finding and reporting/dependency cause without collapsing either. |
| TR-07 | Control-plane access is authenticated and tenant/role scoped. | API-boundary and cross-tenant tests. |
| TR-08 | Outbound HTTP is public HTTPS only and revalidated per redirect/connection. | DNS rebinding, private/special IP, redirect, port, TLS, size, and timeout tests. |
| TR-09 | Persistence migrations are forward-only, idempotent, inspected before use, and rollback-documented. | Legacy/current schema fixtures and rollback rehearsal. |
| TR-10 | Workflows use least privilege, immutable action pins, hash-locked tests, exact-head evidence, and no write token persistence. | Workflow contract tests and GitHub job evidence. |

## Runtime result model

`DetectionResult` aggregates `FamilyAssessment` values. The public semantic
states are `confirmed_finding`, `clean`, `control_effective`,
`dependency_failure`, `reporting_failure`, and `unknown`. Gate satisfaction is
orthogonal: a dependency or reporting failure remains non-passing even when no
source vulnerability is proven.

The registry uses closed `evidence_fields`, required evidence, obligation IDs,
adapter references, implementation references, and three-way fixtures. The
production adapter—not fixture labels or issue text—computes the result.

## Interfaces

- CLI: `appguardrail`, `appguardrail-issue-detection`.
- File: `.appguardrail.json`, normalized findings JSON, SARIF 2.1.0, CycloneDX
  SBOM, packaged registry JSON.
- HTTP: authenticated `/api/v1` scan, history, key, webhook, and health paths.
- Workflow: read-only issue inventory audit and exact focused coverage.
- External producer: `appguardrail.workflow-result-envelope.v1` containing an
  `appguardrail.workflow-result.v1` payload.

Schema changes require versioned readers, negative compatibility fixtures,
migration/rollback notes, and a new ADR when authority or trust changes.

## Security and privacy

Authorization, tenant identity, bounded retention, controlled export, audit
chain integrity, secret-safe diagnostics, and encryption boundaries replace
blanket PII masking. Raw source logs and HMAC keys never enter the registry or
serialized results. CSAP and SOC 2 remain design targets, not assertions.

## Acceptance evidence

1. Focused unit and release-contract suites pass at the exact head.
2. Exact unrounded statement coverage reports no uncovered owned production
   statements; full repository statement/branch and docstring gates remain
   mandatory.
3. The live paginated inventory equals the registry and every digest matches.
4. Mutation-sensitive positive, negative, malformed, missing, extra-field,
   provenance-tamper, and multi-cause tests fail when production logic is
   intentionally broken.
5. Security, packaging, SBOM/provenance, docs, and protected-main operational
   evidence pass before release.

## Standards and references

The design maps secure-development evidence to NIST SSDF, control assurance to
NIST SP 800-53 Release 5.2.0, analysis interchange to SARIF 2.1.0, and issue
inventory behavior to GitHub's versioned REST API.

National Institute of Standards and Technology. (2022). *Secure software
development framework (SSDF) version 1.1: Recommendations for mitigating the
risk of software vulnerabilities* (NIST SP 800-218).
https://doi.org/10.6028/NIST.SP.800-218

National Institute of Standards and Technology. (2025). *Security and privacy
controls for information systems and organizations* (NIST SP 800-53, Release
5.2.0). https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final

OASIS Open. (2020). *Static analysis results interchange format (SARIF)
version 2.1.0*. https://docs.oasis-open.org/sarif/sarif/v2.1.0/

GitHub. (2026). *REST API endpoints for issues* (API version 2022-11-28).
https://docs.github.com/en/rest/issues/issues?apiVersion=2022-11-28
