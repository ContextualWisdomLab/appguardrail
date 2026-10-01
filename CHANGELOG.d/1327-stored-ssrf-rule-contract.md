# Stored-SSRF detector recognizes storage-boundary rejection

- Preserve the canonical #1217 DNS-pinned HTTPS transport, persistence, API,
  redirect, and missing-key contracts through an ordinary two-parent restack.
- Expose the transport resolver seam through both URL-validation boundaries so
  regression tests remain deterministic without the host system resolver.
- Treat a direct `set_webhook(...)` call inside `try` with a same-scope
  `except ValueError` rejection as a negative stored-SSRF detector case.
- Retain vulnerable direct, ignored-validator, non-enforcing-guard, and
  unprotected-after-positive-guard flows as positive regression fixtures.
- Detect fail-closed unauthenticated URL validation followed by ordinary
  `urllib` request or redirect dispatch that re-resolves the same hostname,
  while keeping fixed, unrelated, reassigned, connection-time pinned, and
  Bearer-authenticated destinations negative.
