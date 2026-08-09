# AppGuardrail product requirements document

## Product intent

AppGuardrail gives AI-assisted software teams a security guardrail that remains
useful from local development through deployment and incident evidence. It
must identify actionable product and control conditions, explain uncertainty,
and preserve evidence without inventing vulnerabilities from failed tooling.

## Users and jobs

- Builders need a dependency-light local scan, safe fix guidance, and a clear
  deploy decision.
- Security reviewers need normalized rule, location, severity, fingerprint,
  provenance, and exact-revision evidence.
- Platform teams need tenant-scoped ingestion, drift, retention, audit, SARIF,
  SBOM, and fail-closed external-gate classification.
- Buyers and auditors need reconstructable requirements, decisions, tests,
  operational controls, and honest certification posture.

## Product requirements

| ID | Requirement | Acceptance |
|---|---|---|
| PR-01 | Scan supported source/configuration paths with native rules and explicitly reported optional engines. | Real positive and negative fixtures; no unavailable engine reported as clean. |
| PR-02 | Normalize findings for CLI, JSON, SARIF, reports, console, and deploy gates. | Stable rule/location/fingerprint identity across outputs. |
| PR-03 | Preserve standalone CLI use and typed MSA integration. | CLI works without the control plane; consumers use documented JSON/SARIF/HTTP contracts. |
| PR-04 | Isolate tenant data and privileged operations. | AuthN, role, ownership, retention, and cross-tenant tests pass. |
| PR-05 | Prevent stored and time-of-use SSRF in outbound delivery. | Scheme, DNS/IP, redirect, TLS, size, and timeout tests fail closed. |
| PR-06 | Treat every AppGuardrail GitHub issue as a retained detector requirement. | Complete paginated issue audit and executable issue→claim→detector trace with no exclusions. |
| PR-07 | Distinguish finding, clean, effective control, dependency failure, reporting failure, and unknown. | Positive, negative, malformed, missing, multi-cause, and inconclusive evidence tests. |
| PR-08 | Preserve privacy without blanket PII masking. | Purpose-bound access, tenant/service identity, encryption boundaries, retention, audit, and controlled export. |
| PR-09 | Produce release and acquisition evidence without unsupported compliance claims. | CI/security/coverage/SBOM/provenance/rollback evidence and explicit CSAP/SOC 2 target wording. |

## Non-goals

AppGuardrail does not replace a human penetration test, make a failed workflow
equivalent to a vulnerability, execute untrusted issue prose, bypass protected
resources to fetch evidence, or grant certification. Model output is advisory
unless a deterministic production contract validates it.

## Experience principles

- Show `clean` only with complete authoritative evidence.
- Show the exact next action for incomplete or dependency-blocked evidence.
- Keep security language factual and separate source defects from control-plane
  or provider failures.
- Keep keyboard and assistive-technology paths equivalent to pointer paths.

## Delivery status

- `IMPLEMENTED_ON_PROTECTED_MAIN`: CLI/rule scanning, normalized findings,
  SARIF, reports, SBOM, SQLite control plane, tenant roles, audit/retention,
  console, and pinned HTTPS primitives.
- `ACTIVE_PR`: complete issue-derived registry, signed workflow-result evidence,
  lifecycle audit, canonical architecture pack, and efficacy contracts.
- `ACCEPTED_TARGET_ARCHITECTURE`: producer-side adapters emit authenticated,
  structured evidence envelopes at every external gate.
- `PLANNED`: managed-store implementation and horizontally scaled control plane.

## Success measures

The release gate requires zero excluded issues, zero unsupported clean results,
100% owned production coverage/docstrings, mutation-sensitive detector tests,
no critical/high unresolved finding, exact-head CI evidence, and rollback proof.
Operational measures are defined in `docs/OPERABILITY.md`.
