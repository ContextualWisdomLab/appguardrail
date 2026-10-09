# AppGuardrail Requirements, Detection, and Evidence Traceability

**Status:** Accepted cross-cutting baseline  
**Last reviewed:** 2026-08-12

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
| privileged `pull_request_target` execution of mutable PR-head code | built-in `github-actions-pull-request-target-untrusted-head-execution` rule | Proposed: issue #132 / `.github` PR #635 regression, job-local causal analyzer; promote only after protected merge |
| GitHub Actions versioned registry package bound to npm auto-install | built-in `github-actions-runtime-package-without-integrity` rule | Proposed: bound-package positive and local/unbound/example negative corpus; promote only after protected merge |
| structural Semgrep-style `pattern:` execution by lightweight engine | built-in scanner | not implemented unless a real structural matcher is added; fixtures are not execution |

## Promotion rules

- `implemented-main` requires source/tests on protected `develop`, not an issue/PR description.
- `active-PR` becomes current only after merge plus fresh protected-head required evidence.
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

## Runtime package integrity boundary

The GitHub Actions detector uses a deterministic step/run analyzer rather than a
proximity regex. It is intentionally bounded to one step whose `env` mapping
assigns a versioned registry identity to `*_PACKAGE` and whose immediately
following `run` field places the exact same variable in a supported `npx` or
`npm exec` package-selector position with `-y`/`--yes`. Variable-name boundaries
are exact. Expanded `env:` and compact `- env:` step forms are equivalent, and
same-indent YAML comments do not terminate the step mapping. Blank block-scalar
lines do not end analysis. Heredoc bodies are shell
data and are skipped; analysis resumes after the delimiter. An unquoted heredoc
body counts only when it is redirected to a target and the same step later makes
that exact target executable with `chmod`. This is evidence that auto-install is
admitted, not proof that a download occurred.
Cross-step references, variables used only as ordinary arguments, prefix-colliding
names, unbound local tool names, local tarballs, comments, printed/quoted-heredoc
examples, and non-workflow YAML remain clean. Direct literal package specs, command
prefixes, quoted YAML `run` keys, wider option/order variants, multiple package
variables in one environment mapping, other package managers, composite actions,
reusable workflows, chaining, and indirect expansion remain outside this bounded
analyzer.
The current repository incident remains open until a canonical protected workflow
or immutable released tool contract can scan PR source without trusting PR-owned
bootstrap files.

## Privileged PR-head execution boundary

The GitHub Actions trust-boundary analyzer requires a `pull_request_target`
workflow and evaluates each direct child job independently. A job is in scope
when explicit write authority or a referenced repository secret is present, the
job checks out or shell-materializes
`github.event.pull_request.head.sha`/`ref` or `github.head_ref`, and a later step
executes a repository-local action, script, test, or build command from the
selected tree. One-hop workflow-, job-, and same-step `env` bindings of the
event head are followed into the same shell command segment as checkout/switch,
or from a PR-head fetch into `FETCH_HEAD` worktree creation and entry
commands so the retained fixture reproduces the issue #132 CodeGraph execution
shape after the prevention fix merged in ContextualWisdomLab/.github PR #635.

Metadata-only `pull_request_target` handling, ordinary `pull_request`, trusted
base-SHA checkout, inert output, privilege located only in another job, and a
conservatively recognized scalar or block job-level guard whose every disjunct
excludes PR-target execution are negative fixtures.
Top-level mapping, sequence, inline trigger forms, field ordering, and trailing
YAML comments are equivalent; YAML-looking action inputs, comments, and run
data are not promoted to authority. A same-repository head predicate is
deliberately not an exclusion. The first bounded analyzer does not claim
complete coverage of reusable/composite action internals, cross-job artifacts,
API-downloaded source archives, cross-step or multi-hop environment aliases, container
entrypoints, or third-party actions that fetch contributor content internally.

## Standards/research

Existing repository docs/doctoring/security evidence remain the bibliography/source-of-truth for standards such as SARIF, CycloneDX, GitHub security interfaces, and applicable OWASP/CWE classes. Material new detector classes should add authoritative standard/CWE/OWASP references and APA 7 citations in doctoring where research/standards materially drive implementation.

## Change rule

Every new issue-class detector or product security boundary should add/update a row and its concrete test/evidence path. Stale/queued/cancelled/rate-limited/predecessor checks cannot promote evidence maturity.
