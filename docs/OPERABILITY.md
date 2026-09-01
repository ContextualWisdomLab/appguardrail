# AppGuardrail Operability, Recovery, and Release Guide

**Status:** Accepted operating baseline  
**Last reviewed:** 2026-08-14

## Operating model

AppGuardrail can run as a local/CI scanner, optional multi-tenant control plane, continuous GitHub monitor, source-authoritative evidence verifier, and organization evidence aggregator. The product remains useful when optional external scanners or the control plane are absent; capability/unavailability must be explicit in evidence.

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
- source-authoritative acquisition pass/failure/inconclusive counts;
- stale, duplicate, identity-mismatch, wrong-origin, and upstream API-error counts;
- evidence age and acquisition latency by source repository;
- detector-family executable obligation coverage after bounded vertical-slice integration;
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

### Source-authoritative GitHub Actions evidence

Use the stable CLI exit code before deciding the next action:

- `0`: persist the verified pass evidence and continue the protected workflow;
- `1`: persist the verified failure evidence, block the affected gate, and open/update remediation;
- `2`: treat the result as inconclusive; repair authentication, source identity, freshness, API availability, or malformed data and retry.

For HTTP 403, confirm the token has Actions-read access to the exact private repository. For an identity mismatch, copy the run and job IDs from the same run and verify the owner/repository pair. For stale replay, increase `--max-age-hours` only to the approved historical interval; do not disable freshness. For duplicate digest, reuse the existing immutable evidence record. For API/proxy errors, preserve the bounded error code but never log the credential or response body.

The acquirer intentionally has no internal retry loop. The caller may apply bounded retry only for transient transport or 5xx failures after distinguishing them from deterministic 4xx, identity, freshness, and validation failures. Every retry reacquires both run and job from the fixed API origin and revalidates the full contract.

### External engine

Verify installation/version/config/authorization and distinguish provider/tool infrastructure from target vulnerability. One transient rerun may be appropriate after RCA; repeated retries are not a substitute for fixing deterministic failure.

### Control plane

Preserve scan/audit state, restore SQLite/managed database from verified backup when necessary, rotate/revoke compromised API keys, and revalidate tenant ownership before resuming writes. Schema changes require forward migration and rollback/recovery evidence.

### Webhook

On destination-policy failure, do not send. The current generic unauthenticated webhook path is **at-most-once per local scan event**: after destination validation it makes one best-effort POST and does not automatically retry a transport failure. Record only bounded non-secret delivery evidence; do not create an implicit retry loop that can duplicate receiver-side effects.

If retries are introduced later, they require a versioned delivery contract before enablement: a stable `delivery_id` persisted across attempts, receiver-side deduplication on that identifier, destination and redirect revalidation for every attempt, bounded response/error evidence, capped retry count/backoff, and explicit terminal failure state. Without those controls, retries remain prohibited rather than “best effort.”

For both the current one-shot send and any future retry, every send attempt and redirect hop must resolve and evaluate all destination addresses under the current policy. The connector rejects every private, loopback, link-local, metadata, unspecified, multicast, or reserved address and uses connection-time address pinning (or an equivalently strong connector) to prevent DNS rebinding between validation and connect. It retains the original hostname for TLS SNI and certificate verification, bounds redirects, and verifies that the connected peer address is one of the approved addresses before sending request bytes. Contract tests must exercise rebinding, mixed public/private answers, redirects to denied ranges, and peer-address mismatch; a stored `valid` flag or prior DNS result is never authorization for a later connection.

## Stored SSRF operation

Webhook destination validation must be revisited when DNS resolution/redirect conditions can change between storage and execution. A stored `valid` flag alone is not permanent authorization to access an arbitrary resolved network endpoint.

## Issue-to-detector audit operation

Historical PR #911 remains an inventory prototype and must not be run as if it were protected-branch executable coverage. Issue #938/PR #939 establishes one bounded source-authoritative Actions evidence contract. Extend coverage only by adding a new authoritative acquirer/probe, independent oracle, mutation evidence, production entrypoint, and exact-head gates for each detector family.

## Upgrade and rollback

1. review CHANGELOG/ADR/detector/acquirer changes;
2. run full detector/security/control-plane and source-evidence suites;
3. compare finding/evidence sets on representative benchmark repositories;
4. rehearse persistent schema migration/rollback if changed;
5. canary continuous monitor/control plane where deployed;
6. retain previous package/image/db backup until new evidence is accepted;
7. rollback software/config on regression and re-run the benchmark scan and evidence replay.

## Release gate

Release only from exact protected head with all required CI/security/review, 100% production statement/branch coverage and docs, detector-obligation and source-authority evidence, package/SBOM/provenance, persistent-state migration/recovery, control-plane auth/network security, CHANGELOG/version, and post-publish smoke. A merged detector or acquirer PR is not a release by itself.
