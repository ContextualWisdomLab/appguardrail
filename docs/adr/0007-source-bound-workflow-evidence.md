# ADR-0007: Bind workflow detector results to acquired source evidence

**Status:** Accepted
**Date:** 2026-08-20

## Context

Historical security workflow failures are useful issue inputs, but a workflow
name, issue body, or caller-provided `pass`/`fail` field cannot prove a
vulnerability. The collector must distinguish a completed clean job, a failed
security control, and evidence that is unavailable, stale, malformed,
duplicated, or from an unknown detector family.

## Decision

The production GitHub Actions collector keeps its legacy finding envelope only
as a compatibility boundary and adds a canonical
`appguardrail.source-bound-workflow-evidence.v1` envelope. It binds:

- atomic cause `security_workflow_control_failure` and obligation
  `security-gate-completion`;
- fixed `probe_ref` and `acquirer_ref` for the GitHub Actions REST run/job
  source;
- repository, 40-hex revision, generated run/job artifact reference, source
  observation time, acquisition time, and a SHA-256 digest of bounded source
  metadata;
- typed `clean`, `detected`, or `unknown` assessment plus an evidence digest.

The assessment is derived from the acquired job conclusion. Caller-supplied
assessment or digest fields are ignored. `detected` means the security
workflow control failed; it does not confirm a product vulnerability. Any
trust-boundary ambiguity fails closed to `unknown`, and raw logs are not
persisted or copied to the target issue/control plane.

The existing IssueOps and SQLite control-plane envelopes preserve canonical
evidence as nested data. The source-bound path is exercised by the collector
CLI, IssueOps publication, and control-plane scan detail; legacy records remain
readable without being promoted to canonical source-bound evidence. The
collector publishes only `detected` assessments; malformed, stale, duplicate,
unavailable, or otherwise `unknown` evidence is excluded from the security
failure issue path rather than being treated as a finding.

## Consequences

This gives issue detection a bounded, independently sourced proof chain while
retaining compatibility with existing issue deduplication and scan storage. It
does not claim universal SAST/DAST efficacy: workflow infrastructure failures,
unavailable external scanners, and application vulnerabilities still require
their own source evidence and detector families.

## References

GitHub. (n.d.). *REST API endpoints for workflow runs and jobs*. Retrieved
August 20, 2026, from https://docs.github.com/en/rest/actions/workflow-runs
