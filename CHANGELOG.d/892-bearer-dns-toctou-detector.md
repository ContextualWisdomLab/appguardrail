## Security

- Add the HIGH built-in Bearer DNS-rebinding TOCTOU detector family for Python `urllib` flows that validate a URL before dispatch but allow the network client to make a second DNS decision. The source-backed regression corpus preserves the pre-PR #898 vulnerable flow and the protected DNS-pinned HTTPS repair for security issue #892.
- Track post-construction request state instead of treating the original constructor as permanently authoritative: opaque/dynamic Authorization replacement, header mapping replacement/clearing, and unrelated `Request.full_url` mutation terminate stale credential or destination provenance. A narrowly scoped companion rule keeps provably Bearer-valued variable replacements detectable, while self-derived destination mutations remain positive.
