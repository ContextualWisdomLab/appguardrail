# Rust authentication secret environment-source detector

## Security contract

Rule `rust-auth-secret-raw-env-runtime-source` detects one bounded Rust source family observed in `ContextualWisdomLab/wardnet`: administrator authentication tokens are read directly from `std::env::var(...)` at the runtime authentication configuration/parser boundary.

The source-authoritative positive is Wardnet commit `867d3186652bca1277aa9f08b2d312bbd71e0beb`, `src/lib.rs` blob `15ac355b052a38daac13c36ad0a5fbac5443249e`. The reviewed repair is PR #55 head `ab294c4cb2cc25f2369cf203dc81a65ec071dda7`, blob `fce07f799369607771ad6f5b474c94d7df9bb708`, where environment/file values are bootstrap transports into `CredentialRegistry` and runtime authentication consumes `get_credential(...)` results.

This detector does **not** assert that every environment-variable use is a vulnerability. It is intentionally limited to the source-derived administrator-token forms `ADMIN_TOKEN` and `ADMIN_TOKENS` at the observed Rust auth sinks.

## Why the boundary matters

CWE-526 identifies cleartext sensitive information stored in environment variables as a mappable weakness because process environment data may be visible to other processes and can leak into messages, headers, logs, dumps, or other outputs. OWASP's Secrets Management guidance recommends designated secret-management solutions and notes that environment variables are broadly accessible in process contexts and are not recommended when stronger injection/storage mechanisms are feasible.

Wardnet's reviewed repair preserves environment variables as an optional bootstrap transport but removes them as the runtime authentication source of truth. AppGuardrail therefore treats the repaired registry path as a negative oracle rather than flagging every bootstrap read.

## Remediation boundary

For the matched administrator-token flows:

1. ingest bootstrap transport once into a dedicated credential/secret abstraction;
2. make runtime authentication consume the abstraction, not repeated direct environment reads;
3. apply least privilege, rotation, revocation, audit, and non-disclosure controls to the underlying secret store;
4. never log or expose the secret value merely to prove configuration state.

A process-local registry improves source-of-truth separation but does not by itself provide durable encryption, rotation, or external secret-manager guarantees; those are separate product controls.

## Deliberate limitations

The rule is not a general Rust taint engine. It currently covers only the exact source-backed direct assignments/parsing shapes for `ADMIN_TOKEN` and `ADMIN_TOKENS`. Alternate environment APIs, renamed secrets, helper/cross-file flows, macro expansion, other authentication frameworks, non-Rust languages, and cases where an environment value is already transformed by an independently verified secret boundary require separate detector obligations.

The rule is loaded as `generic` because AppGuardrail's current language-profile registry does not yet expose Rust as a first-class scan axis; its Rust-specific syntax plus `std::env::var`, `ADMIN_TOKEN`, and `admin_token` prefilters keep evaluation bounded. Promoting Rust to a first-class language axis is a separate capability change and is not claimed by this detector.

## Standards and primary references

- Common Weakness Enumeration. (2026). *CWE-526: Cleartext storage of sensitive information in an environment variable (Version 4.20).* MITRE. https://cwe.mitre.org/data/definitions/526.html
- Open Worldwide Application Security Project. (2026). *Secrets management cheat sheet.* OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- Joint Task Force. (2020). *Security and privacy controls for information systems and organizations (NIST Special Publication 800-53, Revision 5).* National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-53r5

NIST SP 800-53's authenticator-management family provides the broader governance context for managing authenticators throughout their lifecycle; CWE-526 and OWASP provide the source-specific environment-variable and secret-management rationale used by this rule.