# Java Spring tenant-authorization scope detector

## Status

Active source-derived SAST contract for `java-spring-admin-discarded-tenant-context`.
The detector is intentionally narrower than a general Java authorization or BOLA engine.

## Source-authoritative provenance

AppGuardrail issue #550 is collector provenance, not vulnerability proof. It records a
Strix security workflow event for `ContextualWisdomLab/clearfolio` PR #240 at head
`0eb7fa9cfc56062983f5337228ca3a7317cf17a8`.

Independent source inspection establishes the reusable weakness:

- source repository: `ContextualWisdomLab/clearfolio`
- collector/source PR: #240
- vulnerable revision: `0eb7fa9cfc56062983f5337228ca3a7317cf17a8`
- vulnerable `AdminController.java` blob: `5086b1d3797a9c32831900d09d93d8df44c5e13a`
- superseding reviewed source PR named by #240: #172
- reviewed fixed-candidate revision: `f4ae8dd695afe1dd41decbc7e6b2a11d0ee5e461`
- reviewed fixed-candidate blob: `872f0a66ea6dc8da95f8327e3d4cf40d3c08689f`

PR #172 is closed and was not merged, so its source is a reviewed negative oracle rather
than protected-branch shipped truth. The detector claim therefore rests on the exact
vulnerable source shape plus an independently authored, reviewed remediation boundary;
it does not claim that Clearfolio has shipped that candidate.

The vulnerable controller calls `tenantAccessService.require(...)` with an admin
permission but discards the returned tenant authorization context. It then reads the
global conversion-job collection or mutates a job by identifier without carrying tenant
identity to the operation. The fixed candidate captures a `TenantContext`, filters list
results by `context.tenantId()`, and passes the same context to mutation services.

## Detector contract

The HIGH-severity rule matches only when all of these source signals are present in the
same bounded Spring handler:

1. a Spring request-mapping annotation whose literal route includes `/admin/`;
2. a standalone `tenantAccessService.require(...)` or `requireSigned(...)` call using
   `TenantPermissions.ADMIN_READ` or `ADMIN_WRITE`, where the return value is discarded;
3. a subsequent observed tenant-sensitive `conversionService` call to `getAllJobs`,
   `deleteJob`, or `retryDeadLettered`; and
4. no intervening Spring request-mapping boundary.

The packaged rule is additionally guarded by `/admin/`, `tenantAccessService`, and
`TenantPermissions.ADMIN_` prefilters before the multiline expression is evaluated.
Production regression coverage exercises `scanner.cli.appguardrail._scan_file`, not only
the expression in isolation.

## Customer action / remediation

Treat the permission check and tenant identity as one authorization decision. Capture the
returned `TenantContext` and carry it to the trusted service/data boundary for each read
or mutation. For collection reads, apply a tenant predicate before data is returned. For
object operations, bind the object lookup or mutation to the authorized tenant and use a
non-disclosing not-found outcome for missing and cross-tenant objects where appropriate.

If the endpoint is genuinely platform-global rather than tenant-admin scoped, use an
explicitly distinct platform-administrator trust domain and service contract so tenant
and platform authority cannot be confused by callers or reviewers.

## False-positive and false-negative boundary

This rule deliberately does **not** claim:

- generic Java/Spring authorization analysis;
- cross-file or interprocedural dataflow;
- custom access-service names, permission enums, or tenant context types;
- annotation-only or framework-provided object authorization;
- proof that a discarded context is unsafe when a separately verifiable tenant boundary
  exists outside the bounded handler;
- platform-global administrator semantics; or
- every BOLA/IDOR shape involving user-controlled identifiers.

Assigning the tenant context and consuming it for controller-side tenant filtering is a
negative oracle. Passing it into the service mutation boundary is also a negative oracle.
These exclusions favor a narrow, source-proven signature over speculative recall.

## Standards mapping

- CWE-863, *Incorrect Authorization*: the product performs an authorization check but
  applies it incorrectly to the protected operation.
- OWASP ASVS 5.0.0 V8.2.2: access to specific data items is restricted to explicitly
  authorized consumers.
- OWASP ASVS 5.0.0 V8.3.1: authorization rules are enforced at a trusted service layer.
- OWASP ASVS 5.0.0 V8.4.1: multi-tenant operations must not affect or expose data for an
  unauthorized tenant.
- OWASP API Security Top 10 2023 API1: endpoints acting on object identifiers require
  object-level authorization checks.

## APA 7 references

MITRE. (2026, April 30). *CWE-863: Incorrect authorization (CWE version 4.20).* Common
Weakness Enumeration. https://cwe.mitre.org/data/definitions/863.html

OWASP Foundation. (2023). *API1:2023 broken object level authorization.* OWASP API
Security Top 10. https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/

OWASP Foundation. (2025). *OWASP Application Security Verification Standard 5.0.0: V8
Authorization.* https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md

Spring Security contributors. (2026). *Authorization (Spring Security 7.1.0 reference
documentation).* Spring. https://docs.spring.io/spring-security/reference/features/authorization/index.html
