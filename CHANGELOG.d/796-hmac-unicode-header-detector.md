### Security

- Added the bounded `python-hmac-compare-digest-unicode-header-dos` SAST rule for the NewsDOM bearer-authentication path that passed arbitrary FastAPI `Header()` strings directly to Python `hmac.compare_digest`, where non-ASCII input can raise an uncaught `TypeError`.
- Consolidated AppGuardrail collector provenance issues `#796`, `#802`, `#804`, `#807`, `#808`, and `#811` into one source-backed detector family while preserving their individual event identities; cancelled/failed Strix conclusions remain provenance only.
- Pinned vulnerable NewsDOM source `04491c0e9ac38b9f793029683cebfb8210ccfadd` / blob `4efdad56ed78ed5c0158cdf0d746aedfe72604fe` and the protected fix merged through NewsDOM PR `#539`, head `e22bb76bcf821dfa21eb83938a474c6cf3e7c1e8`, merge `76417bd240398c1a4bf2f6c65d693ea523b179d0`, blob `f61aafc2d6592f4a84c7b02b50cfe4a972623463`.
