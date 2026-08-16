# Python Missing Authentication Secret Fail-Open

## Status

Candidate bounded detector contract for a source-authoritative NewsDOM authentication weakness. This document describes branch-local candidate work until the detector is merged into protected `develop` and reverified there. Collected workflow failures are provenance only; they are not used as proof that source code is vulnerable.

## Source-authoritative replay

- Source repository: `ContextualWisdomLab/newsdom-api`
- Vulnerable source head: `04491c0e9ac38b9f793029683cebfb8210ccfadd`
- Vulnerable `src/newsdom_api/main.py` blob: `4efdad56ed78ed5c0158cdf0d746aedfe72604fe`
- Authoritative reviewed fix: merged PR `#539`, head `e22bb76bcf821dfa21eb83938a474c6cf3e7c1e8`
- Protected merge commit: `76417bd240398c1a4bf2f6c65d693ea523b179d0`
- Fixed `src/newsdom_api/main.py` blob: `f61aafc2d6592f4a84c7b02b50cfe4a972623463`

The vulnerable `require_authorization` function loads the server token, then executes a bare `return` when the token is absent. Because the return occurs inside the authentication guard, the request can continue without any caller authentication whenever the required server-side secret is missing.

The protected repair makes the security state explicit. A dedicated `AuthenticationMode.DISABLED` branch is the only development-profile bypass. In normal authenticated operation, a missing `settings.api_token` returns a controlled `503 Service Unavailable` response before credential comparison. This separates an intentional non-production mode from an accidental missing-secret condition and fails closed for the latter.

This weakness is distinct from the raw-Unicode `hmac.compare_digest` exception covered by candidate PR `#946`. The present rule covers implicit authentication disablement caused by a missing required server secret; the Unicode rule covers an attacker-influenced exception in a configured authentication path. Neither detector subsumes the other.

## Detector contract

Rule `python-auth-secret-missing-fail-open` reports only the bounded Python source shape where all of the following occur in one function:

1. the function name begins with `require`, `verify`, `check`, or `validate` and includes `authorization`, `authentication`, or `auth`;
2. local variable `token` is assigned from a `get_*token(...)` getter or an object `.token` / `.api_token` attribute;
3. `if token is None:` is followed by a bare `return` or `return None`; and
4. the same function contains a `Bearer` authentication signal.

The multiline expression is bounded by the next function definition and finite character windows. The scanner additionally prefilters files for `token is None` and `Bearer` before evaluating the rule. This intentionally trades recall for a narrow, auditable source-backed contract.

The finding is `HIGH`, high-confidence, and maps to `CWE-306 - Missing Authentication for Critical Function`. CWE 4.20 explicitly allows vulnerability mapping for CWE-306. OWASP Top 10:2025 `A07:2025 - Authentication Failures` includes CWE-306 among its mapped weaknesses. OWASP API Security Top 10:2023 API2 likewise treats unauthenticated access to a microservice that should require authentication as a broken-authentication condition.

## Remediation

- Represent authentication-disabled behavior as an explicit development/test profile or policy state; never infer it from a missing secret.
- In authentication-required mode, fail closed when required secret material is unavailable. Depending on service architecture, reject startup/readiness or return a controlled service-unavailable denial before protected work or body processing begins.
- Keep caller-authentication failure (`401`) distinct from server configuration/unavailability (`503`) when that distinction is operationally useful and does not leak sensitive configuration details.
- Do not replace the missing secret with a hardcoded or source-controlled fallback secret.
- Exercise both configured and missing-secret paths through the production request boundary so deployment configuration cannot silently disable authentication.

## Deliberate limitations

This is not a general Python authentication or interprocedural taint analyzer. It intentionally does not claim to detect:

- authentication functions whose names or token variable differ from the bounded contract;
- token acquisition hidden behind aliases, destructuring, dictionaries, or cross-function helpers;
- missing authentication at the route/decorator level where no matching guard exists;
- optional/public endpoints whose product policy legitimately permits unauthenticated access;
- authorization bypasses caused by tenant/role logic after successful authentication;
- hardcoded fallback secrets, which are a separate weakness family; or
- deployment reachability and route criticality that cannot be established from the matched function alone.

A finding therefore means the code contains the source-backed fail-open guard shape, not that AppGuardrail has proven every runtime route reaches the function or that every missing token is attacker-controlled. Product policy and deployment evidence remain part of triage.

## APA 7 references

MITRE. (2026, April 30). *CWE-306: Missing authentication for critical function (CWE Version 4.20).* Common Weakness Enumeration. https://cwe.mitre.org/data/definitions/306.html

Open Worldwide Application Security Project. (2023). *API2:2023 Broken authentication.* OWASP API Security Top 10. https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/

Open Worldwide Application Security Project. (2025). *A07:2025 Authentication failures.* OWASP Top 10:2025. https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/
