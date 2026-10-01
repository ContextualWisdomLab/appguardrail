# Python hostname-unbound local-loopback SSRF detector

**Status:** Source-derived detector slice  
**Rule ID:** `python-ssrf-allow-local-unbound-loopback`  
**Weakness:** CWE-918  
**Collected source family:** EgressWeave PR #1; AppGuardrail Strix collector issues #820, #828, #831, #835, #837, and #850

## Buyer-visible protection

An SSRF guard may deliberately support local-development targets, but that exception cannot be keyed only to the *resolved address*. If enabling `allow_local` makes every loopback address acceptable regardless of the original hostname, a normally remote hostname can resolve or rebind to `127.0.0.1` / `::1` and inherit the local escape hatch.

The source-derived rule detects the exact EgressWeave shape where `_validate_global_address` initializes `is_allowed_local`, enters an unconditional `if policy.allow_local:` branch, and sets `is_allowed_local = True` solely because `ip_address.is_loopback` is true. It does not flag the reviewed repair, which binds local exceptions to the original hostname before accepting the corresponding address class.

## Source-authoritative evidence

Cancelled Strix/OpenCode/Security Scan jobs are collector provenance, not vulnerability proof. The detector is grounded in immutable source objects:

- repository: `ContextualWisdomLab/EgressWeave`;
- vulnerable base head: `271a9bb95d2a6274065e3e5535afbb880dd27a55`;
- vulnerable `src/egressweave/validation.py` blob: `dc5bd8167593167a622de25d27e0f734b8d3eb5a`;
- reviewed fixed head: `81fc0a34cff7e8c90e3f0247342c0c8ee7de3d86`;
- fixed `src/egressweave/validation.py` blob: `7295c7cbf17c5d2b06dd7f77430e6674d2f25320`.

The reviewed fix separates built-in local hostnames from explicitly allowlisted single-label container names, binds both to the original hostname, and limits the latter to loopback, RFC 1918 IPv4, or RFC 4193 IPv6 unique-local ranges. Dotted remote hosts fall through to the normal non-global/special-use rejection path.

## Detection contract

The lightweight signature requires all of the following inside `_validate_global_address`:

1. `is_allowed_local = False`;
2. a standalone `if policy.allow_local:` condition;
3. an immediately nested `if ip_address.is_loopback:`;
4. `is_allowed_local = True` under that address-only condition.

The standalone-colon requirement intentionally excludes `if policy.allow_local and hostname ...` forms. The production prefilter requires the validator name plus the three characteristic local-exception tokens before evaluating the bounded multiline regex.

## Remediation boundary

Bind any non-global address exception to a policy-approved *original hostname* before accepting a resolved address. Keep loopback, private/unique-local, link-local, shared, documentation, benchmarking, unspecified, multicast, and reserved classes distinct according to the product's documented local-development contract rather than treating a broad library predicate as equivalent to the intended allowlist.

Python's `ipaddress` documentation explicitly notes that `is_private` and `is_global` are classification properties with special cases, including shared address space, and that their semantics have changed as the IANA registries evolved. The source fix therefore uses explicit RFC 1918 and RFC 4193 networks for the private local escape hatch instead of assuming that every `is_private` address is an intended application-local destination.

## Declared limitations

This is not a general SSRF/dataflow engine. It intentionally does not claim coverage for:

- allow-local policies implemented under other function or variable names;
- hostname authorization performed in another function or caller;
- resolver cache, connection-pool, redirect, proxy, Unix-socket, or TLS-identity attacks;
- numeric-host parsing or alternate IP representations;
- application-specific private-network allowlists not represented by this source shape;
- the second EgressWeave fix concerning the precise definition of acceptable private/unique-local address ranges unless the hostname-unbound loopback signature is also present.

Broaden this rule only from a new vulnerable source and independent reviewed negative oracle.

## APA 7 references

Hinden, R., & Haberman, B. (2005). *Unique local IPv6 unicast addresses* (RFC 4193). RFC Editor. https://doi.org/10.17487/RFC4193

MITRE Corporation. (2026). *CWE-918: Server-side request forgery (SSRF)* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/918.html

Python Software Foundation. (2026). *ipaddress — IPv4/IPv6 manipulation library* (Python 3.14.6 documentation). https://docs.python.org/3/library/ipaddress.html

Rekhter, Y., Moskowitz, B., Karrenberg, D., de Groot, G. J., & Lear, E. (1996). *Address allocation for private internets* (RFC 1918). RFC Editor. https://doi.org/10.17487/RFC1918
