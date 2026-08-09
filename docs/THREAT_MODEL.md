# AppGuardrail threat model

This threat model complements `SECURITY.md`. It describes product boundaries;
it is not a certification claim.

## Protected assets

- tenant scans, findings, audit events, retention decisions, and API-key hashes;
- exact source/run/head and detector provenance;
- issue requirement and detector integrity;
- workflow-result attestation capabilities;
- deploy decisions, SARIF, reports, and release evidence; and
- availability of the local CLI and optional control plane.

## Trust boundaries

1. Target repositories and uploaded files are untrusted input to scanners.
2. External engine output and workflow logs are untrusted until schema and
   provenance verification succeeds.
3. GitHub issue content defines requirements but is not executable authority.
4. The local process/control plane boundary requires authentication, role, and
   tenant ownership enforcement.
5. DNS, redirects, TLS peers, and webhook response bodies are untrusted at every
   outbound network hop.
6. CI workflows, action pins, runner credentials, and release environments are
   supply-chain boundaries.

## Abuse cases

| ID | Abuse case | Control | Failure state |
|---|---|---|---|
| TM-01 | Issue prose or fixture declares its own finding/clean state. | Closed adapter execution; answer-bearing fields rejected. | `unknown`, gate blocked. |
| TM-02 | Forged external result claims a trusted producer. | HMAC capability, constant-time verification, exact producer/run/head/source and digest binding. | `unknown`, gate blocked. |
| TM-03 | Valid result replayed for another commit or run. | Exact head/run/evidence-reference checks. | Provenance mismatch. |
| TM-04 | Workflow failure is rendered as a source vulnerability. | Separate operational and semantic assessments. | Dependency/reporting/unknown, not finding. |
| TM-05 | Mixed cause hides one condition. | Aggregate independent assessments. | All causes preserved. |
| TM-06 | Tenant reads or mutates another tenant's scans. | API key authentication, role threshold, server-side ownership query. | 401/403/404 without disclosure. |
| TM-07 | Stored webhook targets internal metadata or rebinding address. | Public HTTPS allow policy, resolution pinning, redirect revalidation, bounded response. | Request rejected. |
| TM-08 | Scanner consumes excessive file/log/result input. | File/path/type/size/time bounds and bounded diagnostics. | Explicit incomplete/error result. |
| TM-09 | Registry omits a new or edited issue. | Paginated lifecycle and scheduled digest audit. | CI/audit failure. |
| TM-10 | Dependency or model provider outage is treated as clean. | Complete authoritative evidence required for clean. | `dependency_failure` or `unknown`. |
| TM-11 | Secret or PII is destroyed by blanket masking or leaked in logs. | Purpose-bound authorization, selective disclosure, bounded retention, secret-safe summaries, controlled export. | Audit event and gate block where applicable. |
| TM-12 | Compromised dependency/action alters evidence. | Zero production dependencies, hash-locked tests, immutable action pins, SBOM/provenance. | Release blocked. |

## Privacy model

PII is not indiscriminately masked when it is needed for an authorized security
workflow. Access is purpose-bound and tenant-scoped; exports are controlled;
retention is bounded; privileged use is auditable; secrets are excluded from
reports; and providers/regions must be selected by deployment policy.

## Residual risks

- Shared HMAC capability distribution and rotation are deployment concerns; a
  future asymmetric attestation design may reduce producer key-sharing risk.
- Regex/native rules cannot prove absence of every semantic vulnerability;
  structural/external engines remain explicit and their unavailability blocks
  only the evidence they own.
- SQLite is suitable for the current optional single-process service, not
  declared horizontally scalable production persistence.
- GitHub availability is required for live inventory audit, but not local scan.

## Review triggers

Review this model when a detector family, public evidence schema, trust source,
new persistence backend, model-backed decision, network destination class,
authentication method, or release path changes.
