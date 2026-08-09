# AppGuardrail Operability, Recovery, and Release Guide

**Status:** Accepted operating baseline  
**Last reviewed:** 2026-08-09

## Operating model

AppGuardrail can run as a local/CI scanner, optional multi-tenant control plane, continuous GitHub monitor, and organization evidence aggregator. The product remains useful when optional external scanners or the control plane are absent; capability/unavailability must be explicit in evidence.

## Scan health states

Distinguish:

- `completed_clean` — selected detector/toolset completed with zero findings;
- `completed_findings` — completed with findings;
- `inconclusive` — evidence malformed/insufficient for a detector obligation;
- `engine_unavailable` — selected optional tool absent/unusable;
- `engine_failed` — tool ran but analysis failed;
- `policy_blocked` — finding set violates deploy gate;
- `evidence_untrusted` — workflow/issue provenance cannot be authenticated.

Do not collapse non-completion into “clean.”

## Key SLIs

- scan completion/findings/blocker counts by engine/family;
- detector false-positive/false-negative benchmark where maintained;
- issue-obligation executable coverage after PR #911 integration;
- engine unavailable/failure rate;
- scan/control-plane latency and finding volume;
- new blocker drift count;
- webhook delivery success/SSRF-policy rejection;
- control-plane auth failures and cross-tenant-denial events;
- remediation/rescan closure rate;
- SBOM/evidence bundle provenance completeness;
- scheduler/API/reviewer infrastructure failures distinct from product findings.

## Failure recovery

### Scanner

Fix the first owning detector/adapter or input-classification boundary, add a regression, then rescan the exact target. Do not suppress a finding merely because a fix is inconvenient.

### External engine

Verify installation/version/config/authorization and distinguish provider/tool infrastructure from target vulnerability. One transient rerun may be appropriate after RCA; repeated retries are not a substitute for fixing deterministic failure.

### Control plane

Preserve scan/audit state, restore SQLite/managed database from verified backup when necessary, rotate/revoke compromised API keys, and revalidate tenant ownership before resuming writes. Schema changes require forward migration and rollback/recovery evidence.

### Webhook

On destination-policy failure, do not send. On transport failure, retain bounded non-secret delivery evidence and retry under a capped backoff policy only if the destination remains valid.

## Stored SSRF operation

Webhook destination validation must be revisited when DNS resolution/redirect conditions can change between storage and execution. A stored `valid` flag alone is not permanent authorization to access an arbitrary resolved network endpoint.

## Issue-to-detector audit operation

After PR #911 merges, run the executable audit from authenticated retained issue inventory and closed evidence corpus. Fail if a detectable obligation lacks a detector family or detector execution is inconclusive. Historical issue count alone is not a success metric; obligation execution and evidence provenance are.

## Upgrade and rollback

1. review CHANGELOG/ADR/detector changes;
2. run full detector/security/control-plane suite;
3. compare finding set on representative benchmark repositories;
4. rehearse persistent schema migration/rollback if changed;
5. canary continuous monitor/control plane where deployed;
6. retain previous package/image/db backup until new evidence is accepted;
7. rollback software/config on regression and re-run the benchmark scan.

## Release gate

Release only from exact protected head with all required CI/security/review, 100% production coverage/docs, detector-obligation evidence, package/SBOM/provenance, persistent-state migration/recovery, control-plane auth/network security, CHANGELOG/version, and post-publish smoke. A merged detector PR is not a release by itself.