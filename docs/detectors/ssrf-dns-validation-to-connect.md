# DNS validation-to-connect detector

## Security contract

Rule `python-unauthenticated-urllib-dns-validation-to-connect` detects one
bounded Python `urllib` family: a function rejects a URL when
`_is_safe_url(variable)` fails, then gives that unchanged variable to an
ordinary request, `urlopen`, or redirect dispatch that can resolve the hostname
again. A public answer admitted by validation can therefore differ from the
address used for the connection, producing SSRF through a time-of-check/time-of-use
race.

Issue #1267 supplies the retained incident. The vulnerable protected source is
`appguardrail_core/controlplane.py` at
`2949d30718752ea5915c7713ba227e8c19d9e5bf` (blob
`576b990f13b61eda5c6b5ff3910e820498bfd923`). The reviewed repair is PR #1327
head `892a842765cb1d704ed9236ca08de494074d9551` (blob
`801e9961b9f666efb3b3e22ebfb50d5f0429e6d1`), where
`post_json_pinned_https` resolves and admits one address set per hop, pins the
TCP peer, and preserves the original hostname for TLS identity.

## Preconditions and observable signal

The attacker must influence the outbound hostname or redirect and cause DNS to
return an admitted public answer during validation but a forbidden or different
answer during connection. The detector's observable signal is the same
case-sensitive Python variable crossing the fail-closed validator and a bounded
`urllib` dispatch without reassignment or connection-time pinning.

## Deliberate boundaries

- PR #1080 owns Bearer-authenticated preflight-to-connect detection. This rule
  excludes functions containing case-insensitive lexical `Authorization` or
  `Bearer` evidence across the complete declaration-bounded function scope;
  unrelated occurrences of those words are a documented false-negative boundary.
- PR #944 owns missing redirect revalidation. This rule instead detects a second
  DNS decision even when a redirect handler validates `newurl` before delegating.
- Reassigned destinations or request objects, case-distinct identifiers,
  attributes, aliases, wrappers, positive-only guards, custom clients, and
  cross-function flows are not joined by this bounded matcher.
- Function signatures, pre-guard flow, rejection branches, and dispatch flow
  have explicit character budgets; a rejection-branch line longer than 400
  characters is outside the detector contract rather than being joined to a
  distant sink.
- The scanner identifies the vulnerable coding pattern; it does not prove that
  a particular resolver, proxy, firewall, or service mesh was exploited.

## Remediation

Resolve and validate every address once per hop, reject mixed or non-global
answers, connect only to an admitted address, verify the connected peer, and use
the original hostname for TLS SNI and certificate verification. Reapply the same
policy to each supported redirect and close every response.

## Primary references

- MITRE. (2026). *CWE-367: Time-of-check time-of-use (TOCTOU) race condition*.
  https://cwe.mitre.org/data/definitions/367.html
- MITRE. (2026). *CWE-918: Server-side request forgery (SSRF)*.
  https://cwe.mitre.org/data/definitions/918.html
- Open Worldwide Application Security Project. (2026). *Server-side request
  forgery prevention cheat sheet*. OWASP Cheat Sheet Series.
  https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- Python Software Foundation. (2026). *urllib.request — Extensible library for
  opening URLs*. https://docs.python.org/3/library/urllib.request.html
