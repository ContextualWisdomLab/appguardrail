# AppGuardrail product and technical gap baseline

**Status:** Proposed  
**Evidence date:** 2026-09-19 UTC  
**Protected authority:** `develop@e71d37e7c58118e6764c96ab7c4492fe33eed6f8`

Open pull-request content is integration evidence, not production authority. Promotion requires ordinary protected-branch merge plus fresh exact-head checks and independent review.

## Control-plane outbound security context

| Boundary | Owner | Current evidence | Status | Next acceptance |
|---|---|---|---|---|
| Empty and unresolved URL-host validation | AppGuardrail validators and packaged scanner rule | Draft #1068@`2379b37f05b12af8e22990965d42da2e69b9c611` | Proposed; repository workflows passed, CodeQL compatibility remains fail-closed pending | Terminal exact-head CodeQL and independent review, then protected merge |
| Stored-webhook admission and explicit-clear semantics | AppGuardrail control plane | This stacked successor: RED `fd8bf9f91fdba5abc902de08d396e06efb435f00`; source repair `29436421ca1770c6fafca80a418b5e1adbf81eed` | Proposed | Terminal exact-head Tests, Security, SAST, CodeQL, and independent review |
| Credential-bearing scan delivery | `appguardrail_core.pinned_https` | Protected `develop`; completed issue #892 | Implemented on protected branch | Preserve pinned-address, TLS-hostname, redirect, credential-stripping, and response-bound contracts |
| Drift-webhook delivery | AppGuardrail control plane; issue #1267 | `_send_alert` still validates and reconnects through a second DNS decision | Open security gap | RED rebinding fixture, pinned actual connection for each hop, consistent HTTPS admission/delivery policy, terminal exact-head evidence |

## Invariants

- Direct repository and HTTP API callers must pass the same stored-webhook admission rule; unsafe or malformed destinations never reach SQLite.
- Missing `url` is invalid input. Explicit `null` or an empty string remains the deletion command.
- Empty-host validation does not prove connect-time SSRF resistance.
- DNS-rebinding acceptance requires the actual TCP connection to use the validated address set while retaining the hostname for TLS SNI and certificate verification.
- Generated doctrine, queued checks, predecessor checks, and open PR descriptions cannot promote protected-branch maturity.
