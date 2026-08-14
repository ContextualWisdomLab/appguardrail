# SSRF redirect-autofollow detector

## Security contract

Rule `python-ssrf-redirect-autofollow-after-validation` detects one bounded Python source shape inside a single function body: a URL variable is rejected when `_is_safe_url(variable)` fails, then the same variable is used to construct `urllib.request.Request(...)`, and the request is dispatched with `urllib.request.urlopen(...)` without an intervening redirect-aware opener. The matcher stops at a subsequent `def`, `async def`, or `class` declaration so same-named variables in adjacent functions cannot be joined into one flow. Python's default `HTTPRedirectHandler` handles HTTP redirects; therefore validating only the initial destination does not prove that later redirect hops remain inside the same destination policy.

The source-authoritative positive is `ContextualWisdomLab/appguardrail` commit `5a7cb7e7237532ffb4366b4d4dc758d0df8993fc`, `appguardrail_core/controlplane.py` blob `07300b0f0df3b7c61c9304812836a4b541a67e6b`. The reviewed fixed source is commit `814e8bf982c27d5aba10ba7ab28b2540ce601c3e`, blob `bf74784ecd168685153700150020648e4ee4e806`, which installs `SafeRedirectHandler` through `urllib.request.build_opener(...)` and applies `_is_safe_url(newurl)` on every redirect request.

## Remediation boundary

Do not rely on a one-time URL validation check when the HTTP client can redirect. Either disable redirects or use a redirect handler that applies the same fail-closed destination policy to every hop before connecting. The redirect policy must be at least as strict as the initial SSRF policy and should reject private, loopback, link-local, metadata, non-global, disallowed-scheme, and other forbidden destinations according to the application's supported threat model.

## Deliberate limitations

This rule is intentionally narrower than general SSRF detection. It does not claim coverage for `requests`, `httpx`, `aiohttp`, custom transports, `urllib` calls that skip the observed `_is_safe_url` boundary, helper/cross-file flows, aliases, dynamically imported clients, DNS rebinding after validation, proxy behavior, or redirect policies implemented outside the matched function. A generic unvalidated `urlopen` call is outside this detector family and should be handled by a separate source/sink rule.

The rule uses `_is_safe_url`, `urllib.request`, and `urlopen` prefilters, explicit Python declaration boundaries, and bounded multiline distances so the lightweight scanner does not evaluate or connect the expression across unrelated code.

## Standards and primary references

- Common Weakness Enumeration. (2026). *CWE-918: Server-Side Request Forgery (SSRF), version 4.20*. MITRE. https://cwe.mitre.org/data/definitions/918.html
- Open Worldwide Application Security Project. (2026). *Server Side Request Forgery Prevention Cheat Sheet*. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- Python Software Foundation. (2026). *urllib.request — Extensible library for opening URLs: HTTPRedirectHandler*. Python 3 documentation. https://docs.python.org/3/library/urllib.request.html

OWASP explicitly recommends disabling redirect following in SSRF-sensitive clients when redirects could bypass input validation. Python documents `HTTPRedirectHandler.redirect_request(...)` as the redirect customization point used by `urllib.request`.
