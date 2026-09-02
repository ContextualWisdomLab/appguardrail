# AppGuardrail Requirements, Detection, and Evidence Traceability

**Status:** Accepted cross-cutting baseline  
**Last reviewed:** 2026-09-02

| Requirement / security class | Detector/control boundary | Evidence maturity |
|---|---|---|
| built-in deterministic scanning | `scanner.py`, rule adapters, normalized findings | implemented-main |
| optional Trivy/Bandit/Ruff/Semgrep/ZAP | external-engine adapters | implemented-main when tool present; capability explicit |
| JSON/SARIF findings | reporting serializers | implemented-main |
| deploy gate/exclusions | gate policy | implemented-main |
| safe deterministic autofix | fix engine | implemented-main for supported transforms only |
| multi-tenant scan/history/drift/API keys | control plane | implemented-main |
| webhook config/notification | control plane/network boundary | implemented-main; storage-boundary SSRF hardening integrated through PR #924 |
| buyer/founder/agency/fix-pack reports | report modules | implemented-main |
| CycloneDX SBOM | SBOM module | implemented-main |
| organization buyer evidence | org evidence aggregator | implemented-main |
| RCA-first feasibility scheduler | CI/agent policy | implemented-main |
| every retained issue claim mapped to executable detector obligation | issue-detection audit | PR #911 active-PR |
| authenticated workflow-result detector evidence | issue-detection audit workflow evidence | PR #911 active-PR |
| automatic scanner detection of unsafe stored-webhook SSRF pattern | built-in `python-stored-ssrf-webhook-url` rule | implemented-main through PR #910 for tested Python `set_webhook` direct and one-hop persistence flows; bounded scope |
| bearer-authenticated DNS rebinding prevention | DNS-pinned HTTPS control-plane transport | implemented-main through PR #898 for the reviewed scan-delivery boundary |
| automatic scanner detection of preflight DNS-validation TOCTOU before bearer urllib dispatch | built-in `python-bearer-preflight-dns-toctou`, `python-bearer-preflight-dns-toctou-header-mutation`, `python-bearer-preflight-dns-toctou-multiline-constructor`, and `python-bearer-preflight-dns-toctou-multiline-header-mutation` detector family | integration evidence: PR #1080; source-backed vulnerable/fixed fixtures and production `_scan_file` regressions must remain with the detector family |
| structural Semgrep-style `pattern:` execution by lightweight engine | built-in scanner | not implemented unless a real structural matcher is added; fixtures are not execution |

## Promotion rules

- `implemented-main` requires source/tests on protected `develop`, not an issue/PR description.
- A PR reference records candidate/integration evidence only; `implemented-main` becomes current only after merge plus fresh protected-head required evidence.
- External-engine capability must name the engine and availability; normalization does not convert it into a built-in detector.
- A prevention/hardening change does not automatically promote the matching scanner-detection row; PR #924 and PR #910 were verified and promoted independently.
- An issue registry mapping cannot promote an obligation unless actual detector execution derives its result from independent/closed evidence.

## Issue #911 traceability contract

When PR #911 is accepted, the authoritative obligation system should preserve issue number/claim identity, detector family, evidence fixture/workflow provenance, execution result, and detector rule/finding evidence. Deduplicating equivalent incidents into one detector family is allowed; dropping a retained claim through an exclusion/waiver list is not.

## SSRF traceability contract

For stored webhook/callback SSRF, trace separately:

1. application prevention at configuration storage;
2. execution-time URL/DNS/IP/redirect/egress validation;
3. AppGuardrail scanner rule capable of finding missing prevention in target code;
4. positive vulnerable fixture;
5. fixed negative fixture;
6. control-plane self-regression;
7. exact-head security/review evidence.

Current protected-branch evidence keeps those controls distinct: PR #924 supplies the fail-closed webhook storage boundary, and PR #910 supplies the packaged `python-stored-ssrf-webhook-url` detector plus focused regression corpus. Neither control expands the detector beyond its declared source/sink and flow contract.

## Bearer DNS TOCTOU traceability

Security issue #892 and merged PR #898 establish the runtime defect and repair: a bearer-authenticated control-plane push first validated a URL, then `urllib` made a second DNS decision during connection; the protected repair uses DNS-pinned HTTPS so the actual connection uses the validated public address set while retaining the hostname for TLS identity verification.

PR #1080 is the integration record for the independent scanner obligation. The detector family keeps four executable rule identities rather than overloading one rule ID or forcing unrelated syntax forms through one expression. `python-bearer-preflight-dns-toctou` binds the same-function source-derived path `_is_safe_url(url)` preflight -> endpoint derived from that URL -> executable `urllib.request.Request` whose direct `headers=` argument carries an `Authorization: Bearer ...` credential -> later reviewed re-resolving urllib dispatch. `python-bearer-preflight-dns-toctou-header-mutation` covers the same validated-destination race when Bearer authorization is added or restored on the still-live tracked request after construction. `python-bearer-preflight-dns-toctou-multiline-constructor` and `python-bearer-preflight-dns-toctou-multiline-header-mutation` cover the corresponding reviewed line-wrapped credential forms without changing the defect identity or broadening the transport boundary. The historical vulnerable fixture and the reviewed pinned-HTTPS fixed fixture remain regression oracles. Production `_scan_file` negatives preserve the reviewed false-positive boundary: commented-out request/header/dispatch text cannot donate evidence; request construction and dispatch in mutually exclusive branches cannot form one path; unauthenticated urllib delivery, validation without network dispatch, arbitrary custom/pinned opener transports, and evidence split across sibling functions are not this detector family. Direct `urllib.request.urlopen` and the reviewed `urllib.request.build_opener(SafeRedirectHandler()).open` flow remain positive network sinks because they can repeat hostname resolution after the separate preflight.

The multiline companion rules inherit the same destination, request-identity, credential-state, and reachability barriers as their direct-layout family members. Before Request construction, replacing the validated URL or URL-derived endpoint with an unrelated destination breaks destination provenance. After Request construction, reassigning the endpoint variable alone does not sanitize the already-bound Request; before dispatch, tracked-request replacement, unconditional same-path `return`/`raise`, Authorization removal, or a statically non-Bearer Authorization overwrite terminates the corresponding live request path. Self-derived endpoint/request state remains eligible before it is bound, and a later supported Bearer restoration can re-establish credential provenance. `tests/test_bearer_dns_toctou_multiline_regressions.py` executes these boundaries through production `_scan_file`, including paired vulnerable, sanitized, dead-sink, self-derived, fully multiline constructor-plus-mutation, and remove-then-restore cases.

Request construction is destination- and credential-bound rather than token-text-bound. The tracked endpoint must be the actual `Request` destination through the first positional URL argument or `url=endpoint`; an endpoint mentioned only in another header/argument beside a fixed request URL cannot donate destination provenance. For the primary Request-credential path, `Authorization: Bearer ...` counts only when it is in the supported direct `headers=` argument at Request-call argument indentation; a nested `headers=` expression inside `data=` or another argument is not HTTP-header evidence. Ordinary direct Request keyword arguments such as `data=` and `method=` may appear between the tracked URL argument and the direct `headers=` argument without breaking the path. Replacing the validated URL with an unrelated destination before endpoint derivation breaks preflight provenance, while self-derived transformations of the validated URL preserve it.

Credential-removal and request-replacement barriers are path-sensitive for the supported nested layouts. A same-branch `remove_header("Authorization")`, `headers.pop("Authorization", ...)`, or `del headers["Authorization"]` before dispatch breaks primary-rule bearer provenance unless a supported later Bearer mutation re-establishes credential flow; removal confined to a different branch does not sanitize a dispatch on the branch where the credential remains. Likewise, a same-branch replacement of the tracked request breaks the original path whenever the replacement destination is not the tracked endpoint, regardless of whether the replacement itself carries Bearer credentials. A rebuild that still targets the tracked endpoint remains detectable when credential provenance also remains, while an unauthenticated same-endpoint rebuild is a credential break. An opposite-branch replacement cannot sanitize a sibling branch that still dispatches the original Bearer request. The production review-boundary regressions preserve these paired cases together with first-positional and keyword-URL positives so later regex changes cannot recover precision by creating silent false negatives.

Post-construction Bearer mutation is an independent credential source for the header-mutation subrule and does not require a preceding removal. `add_header("Authorization", "Bearer ...")`, `add_unredirected_header(...)`, or `headers["Authorization"] = "Bearer ..."` can therefore establish the credential-bearing DNS-re-resolution path on an initially unauthenticated tracked Request; the same forms also restore the path after an explicit removal. The mutation path still requires the validated destination and request identity to remain live through the reviewed re-resolving sink, and it breaks provenance when the validated URL/endpoint is replaced before Request construction, the tracked request is replaced before dispatch, a non-Bearer authorization is used instead, or an unconditional same-path `return`/`raise` makes the sink unreachable. Self-derived endpoint updates and request-preserving assignments remain positive so false-positive barriers do not become silent false-negative sanitizers. Bearer-looking text nested in request data is not used as HTTP-header evidence.

Simple self-derived assignments preserve the tracked path when an executable tracked identifier appears before any string literal or comment on the right-hand side, including `endpoint = endpoint + ...`, URL-derived endpoint updates, and `req = req`. An assignment where the tracked name occurs only as quoted data, such as `endpoint = choose("endpoint")` or `req = choose("req")`, is a provenance break and must not create a HIGH finding. More general wrapper/helper-mediated value flow that places a literal before the tracked identifier is outside this bounded regex detector and requires separate executable evidence rather than speculative flow inference. Paired production `_scan_file` regressions keep both the self-derived positives and quoted-name replacement negatives stable.

The detector deliberately does not claim general interprocedural or cross-library DNS-rebinding analysis. Alternative HTTP clients, helper/cross-file flows, differently named validation boundaries, richer credential construction expressions, arbitrary Request argument ordering beyond the supported direct-header layouts, and custom transports whose actual socket connection is independently pinned require separate evidence. Do not infer scanner maturity from the already-merged runtime repair; promotion requires the detector and its regression corpus on protected `develop` plus fresh protected-head required evidence.

## Standards/research

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

## Change rule

Every new issue-class detector or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.
