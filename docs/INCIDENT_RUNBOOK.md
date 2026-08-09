# Issue-detection incident runbook

## Trigger

Use this runbook for false findings, false clean results, missing issue
coverage, stale-head evidence, provenance rejection, secret/log disclosure,
cross-tenant evidence, repeated dependency/reporting failures, or documentation
that overstates delivery state.

## 1. Contain

- Preserve the exact AppGuardrail commit, registry digest, issue, source
  repository, run/job, checked-out head, and bounded error class.
- Stop publication or affected source producers if they can emit false clean or
  disclose sensitive evidence.
- Do not delete the issue requirement, weaken a gate, print raw logs, or rotate
  unrelated credentials.

## 2. Classify

Separate confirmed product/security findings, expected control actions,
dependency failures, reporting failures, evidence/trust/schema failures,
inventory drift, documentation overclaim, and unknown evidence. Preserve every
cause when more than one applies.

## 3. Diagnose

Trace issue → claim → cause contract → source execution → envelope → verifier →
adapter → outcome → gate. Find the first incorrect or missing boundary. Compare
against a known-good run and test competing hypotheses with read-only or
focused probes.

## 4. Recover

- Write a failing regression at the authoritative boundary.
- Repair the smallest root-cause-changing component.
- Rerun focused and full tests on the exact head.
- Reacquire source evidence and rerun protected-main acceptance.
- Repair publication without discarding the upstream result.
- Update registry digest, traceability, ADR, diagrams, and operator guidance
  when the contract changed.

## 5. Close

Closure requires current exact-head checks, no valid unresolved finding,
required independent review, protected-main operational proof, and evidence
that the same failure class is directly detectable. Record residual unknowns
and the exact condition needed to resume them.

## 6. Learn

Search the complete issue inventory and source-producer fleet for the same
failure class. Improve instrumentation, tests, runbooks, and automation exit
criteria. Follow the incident-improvement loop in NIST SP 800-61 Rev. 3; do not
convert one repaired instance into a fleet-wide completion claim.
