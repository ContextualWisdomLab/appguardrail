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
| automatic scanner detection of preflight DNS-validation TOCTOU before bearer urllib dispatch | built-in `python-bearer-preflight-dns-toctou` rule | integration evidence: PR #1080; source-backed vulnerable/fixed fixtures and production `_scan_file` regressions must remain with the detector |
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

PR #1080 is the integration record for the independent scanner obligation. `python-bearer-preflight-dns-toctou` binds the same-function source-derived path `_is_safe_url(url)` preflight -> endpoint derived from that URL -> executable `urllib.request.Request` carrying an `Authorization: Bearer ...` credential -> later reviewed re-resolving urllib dispatch. The credential source accepts the reviewed f-string form and equivalent literal-prefix string concatenation, and ordinary one-line/multiline request syntax or trailing executable-line comments do not erase the path. The historical vulnerable fixture and the reviewed pinned-HTTPS fixed fixture remain regression oracles. Production `_scan_file` negatives preserve the reviewed false-positive boundary: commented-out request/header/dispatch text cannot donate evidence; request construction and dispatch in mutually exclusive branches cannot form one path; unauthenticated urllib delivery, validation without network dispatch, arbitrary custom/pinned opener transports, and evidence split across sibling functions are not this detector class. Direct `urllib.request.urlopen` and the reviewed `urllib.request.build_opener(SafeRedirectHandler()).open` flow remain positive network sinks because they can repeat hostname resolution after the separate preflight.

Request construction is destination- and credential-bound rather than token-text-bound. The tracked endpoint must be the actual `Request` destination through the first positional URL argument or `url=endpoint`; an endpoint mentioned only in another header/argument beside a fixed request URL cannot donate destination provenance. For the primary Request-credential path, `Authorization: Bearer ...` counts only when it is in the supported direct `headers=` argument at Request-call argument indentation; a nested `headers=` expression inside `data=` or another argument is not HTTP-header evidence. Replacing the validated URL with an unrelated destination before endpoint derivation breaks preflight provenance, while self-derived transformations of the validated URL preserve it.

Credential-removal and request-replacement barriers are path-sensitive for the supported nested layouts. A same-branch `remove_header("Authorization")`, `headers.pop("Authorization", ...)`, or `del headers["Authorization"]` before dispatch breaks bearer provenance; removal confined to a different branch does not sanitize a dispatch on the branch where the credential remains. Likewise, a same-branch replacement of the tracked request with an obviously unauthenticated `urllib.request.Request(...)` before the reviewed sink breaks the tracked credential path, while an opposite-branch replacement cannot sanitize a sibling branch that still dispatches the original Bearer request. A replacement that visibly carries Bearer authorization remains positive. The production review-boundary regressions preserve these paired cases together with first-positional and keyword-URL positives so later regex changes cannot recover precision by creating silent false negatives.

Restoring a Bearer credential after one of those explicit removals re-establishes the defect only when the same validated destination and request remain live through the restoration and reviewed re-resolving sink. The supplemental regression path therefore treats direct `urllib.request.urlopen(req)` and `urllib.request.build_opener(SafeRedirectHandler()).open(req)` as positives after a Bearer restoration, but breaks provenance when the validated URL/endpoint is replaced before `Request` construction, the tracked request is replaced before dispatch, or an unconditional same-path `return`/`raise` makes the sink unreachable. Self-derived endpoint updates and request-preserving assignments remain positive so the false-positive barriers do not become silent false-negative sanitizers. In this restoration path, the post-removal `add_header`/`add_unredirected_header` or `headers["Authorization"] = "Bearer ..."` mutation is the authoritative credential source; the earlier `Request` need not already contain a Bearer header, and Bearer-looking text nested in request data is not used as header evidence.

Simple self-derived assignments preserve the tracked path when an executable tracked identifier appears before any string literal or comment on the right-hand side, including `endpoint = endpoint + ...`, URL-derived endpoint updates, and `req = req`. An assignment where the tracked name occurs only as quoted data, such as `endpoint = choose("endpoint")` or `req = choose("req")`, is a provenance break and must not create a HIGH finding. More general wrapper/helper-mediated value flow that places a literal before the tracked identifier is outside this bounded regex detector and requires separate executable evidence rather than speculative flow inference. Paired production `_scan_file` regressions keep both the self-derived positives and quoted-name replacement negatives stable.

The detector deliberately does not claim general interprocedural or cross-library DNS-rebinding analysis. Alternative HTTP clients, helper/cross-file flows, differently named validation boundaries, richer credential construction expressions, arbitrary Request argument ordering beyond the supported direct-header layouts, and custom transports whose actual socket connection is independently pinned require separate evidence. Do not infer scanner maturity from the already-merged runtime repair; promotion requires the detector and its regression corpus on protected `develop` plus fresh protected-head required evidence.

## Standards/research

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

## Change rule

Every new issue-class detector or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.
