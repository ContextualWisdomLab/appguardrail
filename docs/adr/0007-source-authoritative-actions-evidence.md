# ADR-0007: Source-authoritative GitHub Actions evidence

- **Status:** Proposed
- **Date:** 2026-08-14
- **Decision owners:** AppGuardrail maintainers
- **Related:** Issue #938, PR #939

## Context

AppGuardrail historically aggregated workflow failures and issue records, but a caller-supplied Boolean, log label, or registry entry is not independent proof that a security control failed. Enterprise buyers need evidence that binds a decision to the source system that produced it, while still allowing the underlying source object to be independently replayed and audited.

GitHub's REST API exposes exact workflow-run and workflow-job resources and recommends the versioned `application/vnd.github+json` API contract with `X-GitHub-Api-Version: 2022-11-28`. Fine-grained credentials need only repository Actions read access for private resources. RFC 9110 defines HTTP field values containing CR, LF, or NUL as invalid and dangerous and requires recipients to reject or normalize them; AppGuardrail rejects HTTP control characters at its bearer-credential boundary before constructing the `Authorization` field. NIST SP 800-53 Rev. 5 treats audit, accountability, assessment, access control, and supply-chain assurance as related control families; NIST SP 800-218 requires secure-development evidence to be integrated into the software lifecycle. SLSA v1.2 defines provenance as verifiable information describing where, when, and how an artifact or source revision was produced.

## Decision

AppGuardrail SHALL treat an authoritative GitHub REST run/job pair—not a caller assertion—as the source input for GitHub Actions security-outcome evidence.

The production acquirer SHALL:

1. accept an exact `owner/repository`, `run_id`, and `job_id` intent;
2. use only `https://api.github.com` with API version `2022-11-28`;
3. reject redirects, non-JSON responses, responses larger than 2 MiB, HTTP control characters in bearer credentials, and non-object JSON;
4. bind returned repository URLs, run ID, job ID, run ID on the job, and 40-hex head SHA;
5. require completed security-relevant run/job states and completed step states;
6. reject future, stale, malformed, unsupported, duplicate, and non-security evidence;
7. project only bounded metadata and compute a deterministic SHA-256 source identity;
8. exclude bearer credentials, raw logs, annotations, and unrestricted cross-repository content from the evidence envelope;
9. expose stable exit codes: verified pass `0`, verified failure `1`, unavailable/invalid evidence `2`;
10. preserve authorized identifiers and evidence metadata rather than indiscriminately masking them, while relying on least-privilege token scope, purpose binding, encryption, tenant isolation, retention, immutable audit, and field-level authorization at storage and control-plane boundaries.

## Alternatives rejected

### Trust the caller's pass/fail value

Rejected because it cannot distinguish an actual detector from a wrapper around a Boolean and cannot prove source identity.

### Parse raw workflow logs as the primary contract

Rejected for this first slice because logs are larger, less stable, more likely to contain secrets or personal data, and easier to forge through line-oriented output. Logs may become a separate acquirer only with their own size, redaction, provenance, and oracle contract.

### Follow redirects for convenience

Rejected because authenticated cross-origin redirects create a confused-deputy and credential-disclosure boundary. The source origin is fixed and mismatch fails closed.

### Treat issue #911's generated registry as an oracle

Rejected because registry content and fixtures derived from the same source do not constitute independent efficacy evidence. Minimal reusable inventory data may be reviewed separately, but each detector family needs a source-authoritative probe and independent oracle.

## Consequences

### Positive

- buyers can reproduce exactly which GitHub source object produced a decision;
- evidence has a stable duplicate-prevention identity;
- token values and raw logs stay outside the portable result;
- malformed header-control material is rejected before credentials can enter an HTTP field;
- failures, successes, stale evidence, and unavailable evidence are distinguishable;
- the contract can be reused by organization collectors without inheriting caller-assertion semantics.

### Negative

- callers must provide exact run and job identifiers;
- historical replay requires an explicitly larger, still bounded freshness window;
- GitHub REST availability becomes an operational dependency for live acquisition;
- the slice does not by itself prove all AppGuardrail issue families are directly detected.

## Verification

Merge requires:

- true-positive, true-negative, cancelled, malformed, stale, future, duplicate, wrong-origin, wrong-identity, oversized, invalid JSON, unfinished, bearer-control-character, and token-disclosure tests;
- production statement and branch coverage of 100%;
- complete module/class/function/method docstrings;
- exact-head repository Tests, SAST, CodeQL, dependency/supply-chain checks, `appguardrail-scan`, and independent approval;
- documentation and changelog traceability to issue #938.

## References

GitHub. (2026). *REST API endpoints for workflow jobs*. GitHub Docs. https://docs.github.com/en/rest/actions/workflow-jobs

Joint Task Force. (2020). *Security and privacy controls for information systems and organizations* (NIST Special Publication 800-53 Rev. 5, Release 5.2.0). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-53r5

Souppaya, M., Scarfone, K., & Dodson, D. (2022). *Secure software development framework (SSDF) version 1.1: Recommendations for mitigating the risk of software vulnerabilities* (NIST Special Publication 800-218). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-218

Supply-chain Levels for Software Artifacts. (2026). *SLSA specification version 1.2*. Linux Foundation. https://slsa.dev/spec/v1.2/

Bray, T. (Ed.). (2017). *The JavaScript Object Notation (JSON) data interchange format* (RFC 8259). Internet Engineering Task Force. https://doi.org/10.17487/RFC8259

Fielding, R., Nottingham, M., & Reschke, J. (2022). *HTTP semantics* (RFC 9110). Internet Engineering Task Force. https://doi.org/10.17487/RFC9110
