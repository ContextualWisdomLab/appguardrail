# AppGuardrail technical requirements document

## Scope and status

This TRD covers the protected-main AppGuardrail product and the issue-complete
detection target in PR #911. The inventory/classifier foundation is
`ACTIVE_PR`; direct issue-complete detection is `MISSING`, not yet production.

## Technical requirements

| ID | Requirement | Verification boundary |
|---|---|---|
| TR-01 | Python 3.11+ dependency-free production runtime. | Build wheel/sdist and run supported Python matrices. |
| TR-02 | Closed normalized finding and evidence schemas. | Reject unknown, missing, malformed, non-finite, stale, and extra authoritative fields. |
| TR-03 | Complete open-and-closed issue pagination and requirement digest reconciliation. | Compare the live GitHub inventory with the packaged registry on issue lifecycle events and schedule. |
| TR-04 | Each claim binds a callable production adapter and realistic positive/negative/unknown fixtures. | Execute the adapter; registry presence alone is insufficient. |
| TR-05 | Target external results bind exact producer, repository/run/job/attempt/event/head/source-artifact identity, evidence reference, payload digest, and per-producer trust. | Tamper, replay, cross-claim, wrong-source, and missing-trust tests fail closed. |
| TR-06 | Multi-cause results preserve independent assessments. | One observation can return both source finding and reporting/dependency cause without collapsing either. |
| TR-07 | Control-plane access is authenticated and tenant/role scoped. | API-boundary and cross-tenant tests. |
| TR-08 | Outbound HTTP is public HTTPS only and revalidated per redirect/connection. | DNS rebinding, private/special IP, redirect, port, TLS, size, and timeout tests. |
| TR-09 | Persistence migrations are forward-only, idempotent, inspected before use, and rollback-documented. | Legacy/current schema fixtures and rollback rehearsal. |
| TR-10 | Workflows use least privilege, immutable action pins, hash-locked tests, exact-head evidence, and no write token persistence. | Workflow contract tests and GitHub job evidence. |

## Current implementation boundary

PR #911 registers 414 issue identities and 417 rows across 17 classifier
families, but those rows contain only 20 unique family/claim semantics. The
family fixtures repeat synthetic classifier inputs and are not independent
issue-specific black-box oracles. Adapters accept caller-supplied Boolean,
list, log, or signed outcome evidence; they do not collect and independently
inspect every underlying target condition. Formal cause binding is 0/414 and
validated direct detector efficacy is 0/417.

The live workflow compares issue numbers and normalized title/body digests. It
does not execute a production detector against each source run. The HMAC
envelope gives bounded payload provenance under a shared capability, but
repository/source-artifact identity is not bound. It does not verify the
referenced underlying artifact or make an opaque outcome a native AppGuardrail
finding.

## Required next increments

1. Record source repository/run/head, atomic causal chain, trusted collector,
   direct detector, independent oracle fixture, and trust boundary per claim.
2. Reconcile all 403 workflow observations from source evidence before grouping
   only demonstrably identical causal fingerprints.
3. Add vulnerable, fixed, near-miss, malformed, partial, and unknown black-box
   corpora outside the production registry.
4. Prove mutation sensitivity by breaking each decisive detector predicate.
5. Make the live audit execute the same cause-bound production path, then
   record protected-main operational evidence without collapsing unknowns.

## Runtime result model

The active PR has two non-isomorphic result models. `DetectionResult` is emitted
by workflow-cause classification and uses `finding`, `clean`,
`control_blocked`, `dependency_failure`, `reporting_failed`, and
`inconclusive`. `FamilyAssessment` is returned by family/claim evaluation and
uses only `detected`, `clean`, and `unknown`. Neither model aggregates the
other, so the issue claim API does not yet preserve a unified typed cause model.

The target model distinguishes finding, clean, effective/blocked control,
dependency, reporting, and unknown outcomes while keeping gate satisfaction
orthogonal. The unification and migration contract is `MISSING`.

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
   statements. A real branch-coverage gate remains required and cannot be
   claimed from the current line tracer.
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

GitHub. (n.d.). *REST API endpoints for issues* (API version 2022-11-28).
Retrieved August 9, 2026, from
https://docs.github.com/en/rest/issues/issues?apiVersion=2022-11-28
