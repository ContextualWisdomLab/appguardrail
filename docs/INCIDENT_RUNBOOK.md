# Issue-detection incident runbook

## Trigger

Use this runbook for false findings, false clean results, missing issue
coverage, stale-head evidence, provenance rejection, secret/log disclosure,
cross-tenant evidence, repeated dependency/reporting failures, or documentation
that overstates delivery state.

## Ownership, severity, and response clock

Repository/package incidents are owned by the AppGuardrail maintainer for the
exact affected path. Deployed control-plane incidents are owned by the
deploying organization; source-evidence incidents are owned by that producer's
repository or service maintainer. Security-sensitive escalation uses the
private reporting path in `SECURITY.md`.

| Severity | Examples | Required action |
|---|---|---|
| P0 | false clean that can permit release, cross-tenant disclosure, credential/raw-log disclosure, compromised release evidence | Stop the affected release/publication and contain before any further mutation. |
| P1 | missing cause coverage, provenance rejection, mixed-cause loss, audit-chain break | Block the affected gate/lane and begin bounded diagnosis before promotion. |
| P2 | documentation drift with no shipped behavior change, repeated dependency/reporting failure | Keep state non-passing, record the exact resumption condition, and schedule repair. |

There is no staffed on-call roster or approved P0/P1 wall-clock response SLO in
this repository. That boundary is `MISSING` and blocks managed-service GA. Public
security-report response targets remain those in `SECURITY.md`: acknowledgement
within seven days and triage/status within 30 days when feasible. Those targets
do not authorize a release to continue during an active P0/P1 condition.

## Commands and evidence locations

Use the exact commands in `docs/OPERABILITY.md` for full tests, owned statement
coverage, and the read-only issue inventory audit. No supported command exists
yet for source acquisition/live efficacy, HMAC rotation, or production
backup/restore; each is explicitly `MISSING` rather than an operator exercise.

- Git and the PR retain registry, code, docs, ADR, review, and exact-head check
  identity. GitHub/org retention policy controls Actions logs and artifacts.
- The current SQLite runtime retains scan history in the deployment-owned
  database. Automatic purge and backup/restore integration are not implemented.
- Raw authorized source logs and HMAC capabilities remain source-owner data and
  are not copied into the registry or incident record.
- No central incident-evidence store or repository-defined retention period is
  implemented. A deployment must define encrypted storage, access, legal hold,
  retention, and deletion before managed-service operation.

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

## References

National Institute of Standards and Technology. (2025). *Incident response
recommendations and considerations for cybersecurity risk management: A CSF
2.0 community profile* (NIST Special Publication 800-61 Rev. 3).
https://csrc.nist.gov/pubs/sp/800/61/r3/final
