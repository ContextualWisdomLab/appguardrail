# Keyverse SCIM tombstone and health-URL detectors

**Status:** Source-derived detector slice  
**Rules:** `python-scim-put-tombstone-resurrection`, `python-healthcheck-unrestricted-url-scheme`  
**Collected source family:** Keyverse PR #32; AppGuardrail Strix collector issues #576, #577, #823, #824, #826, #832, and #838

## Source-authoritative evidence

Cancelled Strix/OpenCode jobs are collection provenance, not proof of either weakness. Both detector obligations are grounded in the source changes carried by `ContextualWisdomLab/keyverse` PR #32 and independently rechecked against current protected `main`.

Shared source identities:

- vulnerable base head: `938530663fc9c4129fd309f81f8f44b147728b1e`;
- protected fixed head used as the negative authority: `ce207dfd42975db61c82a5963e206fc1db14ac2b`.

SCIM source objects:

- vulnerable `services/account_unification/app/scim.py` blob: `2cb7609c1bd934670cba1a513f64908f8225601f`;
- fixed blob: `4c0b9fbca9d54a9c2237baf3879512ba17a4295d`.

Healthcheck source objects:

- vulnerable `services/account_unification/app/healthcheck.py` blob: `4284510ce94ac7148aeaec860b69b65d538b4acb`;
- fixed blob: `fd33ac621a2c7c86553ee3049e98d7ac91189186`.

The generic Required OpenCode Review collector issues #822, #825, #827, #833, and #839 remain infrastructure/reviewer provenance and are deliberately excluded from this SAST closure family.

## Detector A — SCIM PUT tombstone resurrection

### Buyer-visible protection

Keyverse represents a merged-away duplicate as a tombstone so it cannot authenticate again and stale identity references can still resolve to the survivor. In the vulnerable source, `PUT /scim/v2/Users/{user_id}` checked only that the target existed and then converted the incoming SCIM resource into a complete replacement. The translation path defaults `active` to true when the field is omitted. A routine upstream full-sync could therefore replace the decommissioned representation, reactivate the duplicate, and erase the survivor pointer.

RFC 7644 defines HTTP PUT as a replacement operation: provided read-write/write-only values replace existing values, and omitted non-required attributes may be cleared or defaulted according to the service's schema behavior. AppGuardrail therefore treats a full-replacement sink that omits the application's immutable tombstone check as a workflow-enforcement defect rather than assuming that SCIM itself preserves product-specific merged-account state.

### Detection contract

`python-scim-put-tombstone-resurrection` is a HIGH source-shape rule. It requires, within the same bounded `replace_user` SCIM PUT handler:

1. `@scim_router.put` and `def replace_user`;
2. conversion of the request through `_to_user_account(resource...)`;
3. a later `provisioner.replace_user(user_id, account)` sink;
4. no preceding source-local evidence of `get_user_attribute(...)`, `TOMBSTONE_ATTRIBUTE_KEY`, or `merged_into_user_id`.

The reviewed fixed source is negative because it checks `TOMBSTONE_ATTRIBUTE_KEY` while holding the same per-user operation lock used by merge operations. An independently authored `merged_into_user_id` guard is also negative.

The rule maps to CWE-841, *Improper Enforcement of Behavioral Workflow*. CWE 4.20 allows CWE-841 for vulnerability mapping and describes failures to enforce required behavioral sequencing. The product-specific sequence here is: identify target → establish that the target is not a merged tombstone → perform a full replacement.

### Declared limitations

This is not a general SCIM authorization or identity-lifecycle engine. It does not claim coverage for PATCH/DELETE/POST paths, helper-mediated tombstone checks, remote IdP policy, credential deletion, merge races outside the tested source shape, or other immutable identity states.

## Detector B — unrestricted healthcheck URL scheme

### Buyer-visible protection

The vulnerable container healthcheck accepted a configurable `url: str` and passed it directly to `urllib.request.urlopen`. Python 3.14's standard `urllib.request` opener can contain handlers for HTTP(S), FTP, local files, and other URL types. Keyverse's reviewed repair first rejects initial schemes outside HTTP(S), then uses an `OpenerDirector` populated only with HTTP(S) handlers plus a redirect handler that also rejects non-HTTP(S) targets.

The source commit explicitly characterized the health URL as a container self-probe rather than attacker-controlled input. AppGuardrail therefore reports this detector at **MEDIUM** and labels it defense-in-depth unless a consuming deployment independently establishes that a less-trusted actor can influence the configured URL. The rule must not be presented as proof of remotely exploitable SSRF merely because `urlopen` is dynamic.

### Detection contract

`python-healthcheck-unrestricted-url-scheme` requires:

1. a `main(url: str = DEFAULT_URL)` healthcheck entrypoint;
2. a direct dynamic `urllib.request.urlopen(url...)` call in the same bounded function;
3. no preceding `urlsplit(...)` scheme classification;
4. no `_open_health_url(...)` restricted-opener boundary.

The reviewed HTTP(S)-only opener, an independently authored explicit scheme allow-list, and a literal local self-probe remain negative.

CWE-918 is recorded as the relevant request-forgery class for cases where the configured URL can cross a trust boundary. The detector's severity and documentation preserve the weaker source evidence of the Keyverse self-probe rather than upgrading configuration misuse into a remote-input claim.

### Declared limitations

The rule does not prove URL provenance, deployment configuration authority, DNS rebinding, proxy behavior, redirect host allowlisting, destination IP policy, TLS identity, response-size bounds, or request-header secrecy. Those require separate source-backed obligations.

## APA 7 references

Hunt, P., Grizzle, K., Wahlstroem, E., & Mortimore, C. (2015). *System for cross-domain identity management: Protocol* (RFC 7644). RFC Editor. https://doi.org/10.17487/RFC7644

MITRE Corporation. (2026). *CWE-841: Improper enforcement of behavioral workflow* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/841.html

MITRE Corporation. (2026). *CWE-918: Server-side request forgery (SSRF)* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/918.html

Python Software Foundation. (2026). *urllib.request — Extensible library for opening URLs* (Python 3.14.6 documentation). https://docs.python.org/3/library/urllib.request.html
