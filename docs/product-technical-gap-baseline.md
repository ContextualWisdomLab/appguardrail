# AppGuardrail product and technical gap baseline

**Snapshot:** 2026-08-20
**Authority:** protected `develop` documentation plus live GitHub PR/issue state
**Status:** working baseline; it is not a release or certification claim

## Decision summary

AppGuardrail already has a useful standalone scanner, normalized findings/SARIF,
safe remediation guidance, an optional tenant control plane, external-engine
provenance, and a PR-first security-development loop. The largest buyer gap is
not another detector pattern: it is proving that one detector acquired
source-authoritative evidence, bound it to the control obligation, and produced
an independently verifiable result.

The delivery order is therefore:

1. ship one source-authoritative detector vertical slice;
2. make `Clean Scan` an evidence-qualified state;
3. make remediation evidence safely portable into an agent workflow;
4. harden retention, audit, release provenance, and cross-repository evidence
   as the preceding contracts become production truth.

An open or green PR is not protected-branch behavior. A claim becomes current
only after the exact unchanged head passes its required Checks, review-thread
resolution, applicable independent review, and ordinary protected merge.

## Current product contract

The accepted product and technical baselines define four separable planes:

```text
scan       built-in detectors + optional external engines
remediate  deterministic safe transforms + reviewable fix/verification guidance
control    tenant-isolated scan history, drift, API keys, and webhooks
assurance  SARIF, reports, SBOM, provenance, and CI/release evidence
```

The contract requires executable detector evidence, realistic positive/negative/
inconclusive tests, preserved external provenance, explicit tenant and egress
boundaries, and a `Clean Scan` result only after the selected evidence sources
complete successfully. `docs/PRD.md`, `docs/TRD.md`, `docs/UML.md`,
`docs/TRACEABILITY.md`, `docs/THREAT_MODEL.md`, `docs/TEST_STRATEGY.md`, and
`docs/OPERABILITY.md` are the current source documents. The root
`ARCHITECTURE.md` is the concise navigation document for these contracts; do
not create a duplicate `docs/ARCHITECTURE.md`.

## Live PR and issue evidence

This table records the high-signal work visible during the 2026-08-20 audit.
It intentionally does not promote a PR's proposal, review, or queued Check to
protected-branch truth.

| Work | Live state | Product meaning | Required next proof |
| --- | --- | --- | --- |
| PR #998, Python shell AST detector, head `e2b0637` | open, `develop` target; all repository and dedicated detector Checks terminal-success; current CodeRabbit threads resolved; independent approval absent | High-value detector precision for aliases, nesting, shadowing, and malformed Python | exact-head qualifying approval, protected merge |
| PR #997, browser XSS evidence, head `079b335` | open, `develop` target; repository and browser Checks terminal-success; visible review thread resolved; independent approval absent | Browser-level proof that hostile dashboard content remains inert | exact-head qualifying approval, protected merge |
| PR #999, product/technical gap baseline, this documentation head | open, `develop` target; required Checks queued; review required | Buyer-facing evidence register and a bounded product-development contract | terminal Checks, current review evidence, and protected merge |
| PR #983, Python shell-spawning detector, head `40c4d24` | open, `develop` target; current tree has passed local focused/full tests; required Checks queued after a same-tree follow-up commit; current review evidence is predecessor-bound | Distinguish implicit `os.system`/`os.popen` shells from `subprocess(..., shell=True)` and cover nested arguments | exact-head terminal Checks, current review evidence, protected merge |
| PR #969, dashboard upload proxy, head `9997f00` | open, `develop` target; current head restores HTML `hidden` tree exclusion after an external regression; required Checks and current review queued | Preserve one accessible upload action while keeping native file selection behavior | exact-head terminal Checks, current review evidence, protected merge |
| PR #963, Java tenant authorization detector, head `9cbba72` | open, `develop` target; source-backed fixture and local full tests pass; required Checks and current review queued | Detect discarded tenant authorization context at Spring admin read/mutation sinks | exact-head terminal Checks, current review evidence, protected merge |
| PR #973, GitHub Actions workflow-input injection detector, head `89deac8` | open, `develop` target; required Checks queued; no live review finding observed in the current review API read | Trust-boundary detection for untrusted workflow inputs reaching commands | exact-head SAST, coverage, security, and protected-merge evidence |
| PR #971, Java mutable MultipartFile detector, head `565917c` | open, `develop` target; terminal quality/security Checks passed; CodeRabbit thread resolved; old OpenCode request remains while current-head rerun is queued | Detect unsafe mutable byte-array exposure across Java syntax variants | current-head OpenCode approval, terminal Checks, and protected merge |
| PR #968, fail-open authentication-secret detector, head `4d030ff` | open, `develop` target; terminal quality/security Checks passed; CodeRabbit thread resolved; current OpenCode approval absent | Prevent authentication findings from losing their declared CWE contract | current-head OpenCode approval, terminal Checks, and protected merge |
| PR #966, orphaned workflow registry detector, head `b3f10ad` | open, `develop` target; all repository Checks terminal-success; visible threads resolved; OpenCode request remains; qualifying approval absent | Detect stale workflow registrations before assurance evidence is trusted | exact-head qualifying approval and protected merge |
| PR #954, hostname-unbound loopback SSRF detector, head `f1e2ce5` | open, `develop` target; all repository Checks terminal-success; visible threads resolved; repeated OpenCode requests remain; qualifying approval absent | Prevent hostname-bound SSRF exceptions from accepting loopback targets | exact-head qualifying approval and protected merge |
| PR #930, dashboard state and focus, head `2e96553` | draft, `develop` target; repository Checks terminal-success; visible threads resolved; extensive predecessor OpenCode requests remain; qualifying approval absent | Make scan state, detail focus, external-reference behavior, and read-only console exposure perceivable | current-head review reconciliation, qualifying approval, and protected merge |
| PR #996, reference-dedupe performance, head `51dd28a` | draft, `develop` target; repository Checks terminal-success; review absent; qualifying approval absent | Remove generator-frame allocation without changing reference normalization semantics | reproducible benchmark evidence, current review, and protected merge |
| PR #970, retention-audit diligence posture, head `db06f5e` | open, `develop` target; repository Checks terminal-success; visible threads resolved; OpenCode request remains; qualifying approval absent | Give buyers a non-secret, fail-closed retention and audit posture | exact-head qualifying approval and protected merge |
| PR #967, protected PyPI publication, head `5a48b74` | open, `develop` target; repository Checks terminal-success; OpenCode requests remain; qualifying approval absent | Bind release publication to protected source and installable artifact evidence | exact-head qualifying approval and protected merge |
| PR #972, evidence-qualified clean scans, head `4ba738a` | draft, `develop` target; repository and dedicated assurance Checks terminal-success; visible thread resolved; formal review COMMENTED; independent approval absent | Candidate implementation for the assurance-state gap below | leave Draft only after current-head review policy and qualifying approval; then integrate dashboard/report consumers |
| Issue #938 | open product gap | source-authoritative detector vertical slice | one real source fixture, independent oracle, persisted evidence, and black-box production path |
| Issue #927 | open product gap | buyer cannot distinguish zero findings from completed trusted coverage | evidence-qualified outcome model and accessible dashboard/report parity |
| Issue #928 | open product gap | remediation evidence cannot yet move safely through CSP-compatible agent handoff | CSP-safe listeners, exact text copy, fallback, provenance schema, and UX tests |

The live queue contains additional open PRs and security-failure coordination
issues. The hourly loop must re-read them from GitHub before selecting work;
this snapshot is not a substitute for that query.

## Buyer-facing gap register

| ID | Buyer-visible gap | Current evidence | Smallest valuable slice | Exit evidence |
| --- | --- | --- | --- | --- |
| G-01 | A buyer cannot verify that AppGuardrail itself observed the authoritative source condition rather than receiving a caller assertion. | PRD-FR-002/TRD §3 require the boundary; Issue #938 states the missing vertical slice. | Implement one detector family through `atomic cause → obligation → probe/acquirer → source identity → typed assessment → independent oracle → persisted evidence → API`. | Positive, negative, malformed, unavailable, stale, duplicate, adversarial fixtures; mutation tests; production black-box test; exact source/artifact digest. |
| G-02 | `0 findings` can overstate assurance when detectors, external tools, scope, or provenance are incomplete. | PRD invariant 10 and TRD §7 state the rule; Issue #927 and PR #972 remain active. | Add `clean`, `findings_present`, `incomplete`, `failed`, and `untrusted` outcomes with scope, detector completion, freshness, commit, schema, and provenance fields. | Only fully completed/trusted fixtures render clean; dashboard, JSON, SARIF, reports, and deploy gate agree. |
| G-03 | A developer cannot transfer remediation and evidence into an agent workflow without CSP, clipboard, redaction, or provenance ambiguity. | Issue #928; current dashboard is static and must retain its CSP contract. | Add listener-based copy actions and a versioned deterministic evidence bundle; keep raw suppressed secrets out of the bundle. | hostile text remains inert; success/rejection/fallback are accessible; no duplicate listeners; schema and digest are verified. |
| G-04 | Enterprise buyers need defensible retention, deletion, audit, and recovery semantics for scan evidence. | PRD §7, Issue #871, `docs/controlplane-schema-migration.md`, and current control-plane docs. | Integrate the reviewed retention/audit policy into the live control-plane store/API with tenant ownership and migration rollback. | real migration rehearsal, backup/restore evidence, tenant authorization tests, immutable audit verification, and current-head release proof. |
| G-05 | Acquisition reviewers cannot yet consume one compact, exact-head evidence package spanning source, checks, provenance, and residual gaps. | `docs/OPERABILITY.md` and assurance-plane requirements exist; open PRs remain distributed evidence. | Produce a deterministic buyer evidence bundle that separates observed, unavailable, and inferred facts and binds every claim to SHA/run/artifact identifiers. | independently recomputable digest, no raw secrets, failed/unavailable distinction, protected-head and post-publish smoke evidence. |

## Technical and architecture gaps

- The scanner, control plane, remediation, and assurance planes are described
  separately, but the source-authoritative evidence contract is not yet proven
  end to end by one production detector.
- `ARCHITECTURE.md` is the concise navigation document for the existing
  PRD/TRD/UML/ERD/threat/test/operability contracts; keep it synchronized when
  a boundary changes and do not duplicate those documents.
- External tools remain capability-dependent. Missing, queued, failed, and
  unavailable evidence must remain typed states rather than becoming a clean
  result or a built-in AppGuardrail finding.
- The current repository is Python/stdlib security tooling, not mathematical
  or psychometrics software. No Rust/GPU rewrite is justified by this baseline;
  introduce a native component only for a measured security, isolation, or
  throughput boundary with a stable standalone/MSA contract.
- No database object is added by this baseline. Future schema work must use
  descriptive two-word-or-longer `snake_case` names, normalized relations,
  tenant ownership, migration rollback, and a hot-partition strategy grounded
  in measured workload.
- Authorized PII-bearing work must use tenant isolation, least privilege,
  encryption, immutable audit, purpose binding, retention, and field-level
  authorization. Indiscriminate masking is not an acceptable substitute for
  access control, and this document contains no customer identifiers.
- No Figma file is needed for this documentation-only slice. Any material UI
  change for G-02 or G-03 must first record its Figma File ID in an ADR and
  maintain a reusable design-token/Storybook inventory where the project uses
  a component UI. The current static dashboard is not evidence that Storybook
  coverage exists.

## Governance loop

The scheduler remains PR-first and single-flight:

```text
read live PRs → inspect current-head review/Checks → fix valid findings
→ rerun focused/full evidence → merge only under protection
→ re-read queue → select one reviewed gap → implement → repeat
```

Checks waiting is not a reason to bypass the gate. During a wait, only
non-conflicting diagnostic, documentation, or test work may proceed. Never use
admin merge, force-push, review dismissal, required-check removal, fabricated
runtime evidence, or a model's output as merge/release authority.

## Standards and acceptance basis

This baseline maps its delivery evidence to the following current primary
sources. These references guide controls; they do not constitute CSAP, SOC 2,
or any other certification claim.

### References (APA 7th)

National Institute of Standards and Technology. (2022). *Secure software
development framework (SSDF) version 1.1: Recommendations for mitigating the
risk of software vulnerabilities* (NIST Special Publication 800-218).
https://doi.org/10.6028/NIST.SP.800-218

OWASP Foundation. (2025). *OWASP Application Security Verification Standard
(ASVS) 5.0.0*. https://owasp.org/www-project-application-security-verification-standard/

SLSA. (n.d.). *SLSA specification version 1.2*. Retrieved August 20, 2026,
from https://slsa.dev/spec/v1.2/

## Next action

After the current exact-head PR loop reaches a protected merge, start with
G-01/Issue #938 on `develop`. Keep G-02 and G-03 as separately reviewable
successors unless a live dependency proves stacking is safe. Do not call this
baseline complete until the gap register is re-audited against current PR,
issue, source, and protected-branch evidence.
