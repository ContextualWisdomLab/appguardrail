# DNS-resolution fail-open detector

## Security contract

Rule `python-ssrf-dns-resolution-fail-open` detects a bounded Python validator
that calls `socket.gethostbyname` or `socket.getaddrinfo`, catches
`socket.gaierror`, and still returns literal `True`. DNS failure is missing
security evidence, not proof that an attacker-controlled destination is safe.

Issue #1267 retains both vulnerable generations. The original single-address
validator is commit `dfac26a826689c17e17e243c9cdc2957810f5a22`, blob
`65537cf91bc9549aad1c4d0c6a29116fba603934`. The protected multi-address
validator is commit `2949d30718752ea5915c7713ba227e8c19d9e5bf`, blob
`576b990f13b61eda5c6b5ff3910e820498bfd923`. PR #1327's reviewed repair source
is commit `892a842765cb1d704ed9236ca08de494074d9551`, blob
`801e9961b9f666efb3b3e22ebfb50d5f0429e6d1`; it converts destination-validation
failure into rejection and uses the DNS-pinned transport.

## Preconditions and observable signal

An attacker must influence a hostname that reaches the validator while DNS
lookup fails, is blocked, or returns no usable evidence. The observable signal
is one declaration-bounded function containing a supported resolver call, a
`gaierror` handler that either returns `True` directly or contains only bounded
comment/`pass` lines, and a following literal `return True` after any bounded
fail-closed sibling exception handlers. The function name must contain a
case-insensitive URL-policy signal: `safe`, `valid`, `allow`, `permit`,
`destination`, or `url`.

## Deliberate boundaries

- Explicit `return False` and `raise` handlers are negative.
- A handler followed by an enforcing `if not resolved: return False` is negative.
- Resolver failure in one function and an allow decision in another are not joined.
- The supported resolver call and `gaierror` handler must belong to the same
  `try` statement; nested `try`, function, or class declarations terminate that
  join.
- Admission must be literal `return True` followed only by whitespace, an
  optional comment, and the line end. Boolean or other expressions are excluded.
- Aliased resolver APIs, wrapper helpers, other exception types, dynamic return
  values, and paths beyond the declaration and character budgets are
  inconclusive. They are not claimed safe.
- Generic resolver utilities without a URL-policy function-name signal are
  excluded to avoid treating best-effort DNS probes as security validators.
- Conditional exception reachability and general path-sensitive data flow are
  outside this regex rule. The scanner reports the supported causal pattern; it
  does not prove runtime exploitability.
- The sibling `python-unauthenticated-urllib-dns-validation-to-connect` rule
  detects a separate TOCTOU class after successful validation. Neither rule
  substitutes for connection-time DNS pinning.

## Remediation

Fail closed on resolver errors, empty answers, malformed addresses, and mixed or
non-global answer sets. Resolve and validate once per supported hop, connect only
to an admitted address, verify the connected peer, preserve the original
hostname for TLS identity, and reapply the policy to every redirect.

## Primary references

- MITRE. (2026). *CWE-918: Server-side request forgery (SSRF)*.
  https://cwe.mitre.org/data/definitions/918.html
- Open Worldwide Application Security Project. (2026). *Server-side request
  forgery prevention cheat sheet*. OWASP Cheat Sheet Series.
  https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- Python Software Foundation. (2026). *socket — Low-level networking interface*.
  https://docs.python.org/3/library/socket.html
