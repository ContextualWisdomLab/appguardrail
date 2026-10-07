# Hostname-unbound local-address exception detector

**Status:** Proposed in PR #1327
**Rule:** `python-ssrf-hostname-unbound-local-address-exception`
**Issue:** #850
**Class:** CWE-918 / OWASP A10:2021

## Root cause

EgressWeave's vulnerable address validator put loopback admission beneath a
global `policy.allow_local` switch. It did not first bind that exception to the
original requested hostname. A public hostname that changed its DNS answer to
loopback could therefore inherit a development-only exception.

## Preconditions and observable signal

The bounded detector requires one Python address-policy function containing a
standalone `if <policy>.allow_local:` branch, an immediately nested
`if <address>.is_loopback:` branch, and direct Boolean admission through
`<flag> = True`. The `allow_local` token is an execution prefilter.

## Positive and negative boundaries

The exact vulnerable oracle is EgressWeave head
`2d9dc094409bdc3574bcee6b9a5c52ea920b3936`, blob
`caea83981a50407528ce3d45d16a5643d5ef0fbf`. Renamed identifiers with the
same bounded code shape are positive.

The exact fixed oracle is head
`81fc0a34cff7e8c90e3f0247342c0c8ee7de3d86`, blob
`7295c7cbf17c5d2b06dd7f77430e6674d2f25320`. It checks the original hostname
before admitting either a local-development or explicitly allowlisted address.
Hostname-bound combined conditions, fail-closed policy, and observation-only
branches are negative. A direct fail-closed membership guard is also negative
when it binds `hostname` to an explicitly local configuration attribute before,
and at the same control-flow indentation as, the local-address branch. Generic
allowed/trusted-host collections, later guards, and conditionally nested guards
do not prove a local-only exception and remain positive.

Aliases, helper wrappers, dictionary access, cross-function flows, non-Boolean
admission, and other alternative branch shapes are explicit false negatives
until independent incidents justify safely widening the contract.
The rule does not claim proof that DNS is pinned at connection time.

## Owner repair and release boundary

EgressWeave PR #1 fixed the canonical owner and merged as
`6f337b67efd985bdfcb16646fa3726709bd2e17e`. No immutable release ref for that
fix was present when this corpus was added, so consumer promotion remains
blocked on an owner release and version bump. AppGuardrail retains the incident
as a regression oracle; it does not copy or replace EgressWeave's domain fix.
