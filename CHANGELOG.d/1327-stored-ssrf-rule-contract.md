# Stored-SSRF detector recognizes storage-boundary rejection

- Preserve the canonical #1217 DNS-pinned HTTPS transport, persistence, API,
  redirect, and missing-key contracts through an ordinary two-parent restack.
- Treat a direct `set_webhook(...)` call inside `try` with a same-scope
  `except ValueError` rejection as a negative stored-SSRF detector case.
- Retain vulnerable direct, ignored-validator, non-enforcing-guard, and
  unprotected-after-positive-guard flows as positive regression fixtures.
