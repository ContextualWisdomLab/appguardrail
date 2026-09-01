# AppGuardrail Architecture

**Status:** Accepted as-built/target architecture with maturity labels  
**Last reviewed:** 2026-08-14

## Architectural goal

AppGuardrail converts application/security evidence into deterministic findings, reviewable remediation, continuous policy gates, and longitudinal assurance without conflating optional external scanners, issue metadata, or historical coordination with executable detection truth.

## Component view

```mermaid
flowchart LR
    TARGET[Untrusted target repository/app]
    DISC[Discovery/normalization]
    BUILTIN[Built-in detector engine]
    EXT[Optional external engines]
    FIND[Normalized findings]
    GATE[Deploy gate]
    FIX[Safe fix / fix-pack]
    SARIF[SARIF / reports / SBOM]
    CP[Control plane]
    DASH[Dashboard / buyer evidence]
    ISSUE[Issue-to-detection audit]

    TARGET --> DISC
    DISC --> BUILTIN
    TARGET --> EXT
    BUILTIN --> FIND
    EXT --> FIND
    FIND --> GATE
    FIND --> FIX
    FIND --> SARIF
    FIND --> CP
    CP --> DASH
    ISSUE --> BUILTIN
    ISSUE --> EXT
```

## Detector authority

The detector that observes evidence is authoritative for its finding. `scanner/rules/*.yml` is not automatically executable in full: supported `pattern-regex` entries can be evaluated by the lightweight engine, while Semgrep-style structural `pattern:` fixtures remain non-executable by the built-in matcher unless explicitly routed to a working structural engine.

External engines retain their own engine/rule/version provenance. AppGuardrail normalizes their output but does not claim their analysis was performed internally.

## Issue-to-detection boundary

```mermaid
flowchart LR
    HIST[Independent issue/claim inventory]
    REG[Detection obligation registry]
    ADAPT[Detector-family adapter]
    DET[Actual detector]
    EV[Closed evidence fixture or authenticated workflow result]
    RES[pass/fail/inconclusive obligation result]

    HIST --> REG
    REG --> ADAPT
    EV --> ADAPT
    ADAPT --> DET
    DET --> RES
```

A registry maps requirement identity to executable detector family; it cannot assert the detector answer. Historical PR #911 remains a non-authoritative inventory prototype. Issue #938 and PR #939 replace its broad draft with one bounded, source-authoritative detector vertical slice.

## Source-authoritative GitHub Actions evidence

```mermaid
flowchart LR
    INTENT[Exact repository, run ID, job ID]
    API[GitHub REST API 2022-11-28]
    RUN[Authoritative workflow run object]
    JOB[Authoritative workflow job object]
    VALID[Identity, terminal-state, freshness validation]
    HASH[Canonical SHA-256 source identity]
    DECISION[Verified pass/failure evidence]

    INTENT --> API
    API --> RUN
    API --> JOB
    RUN --> VALID
    JOB --> VALID
    VALID --> HASH
    HASH --> DECISION
```

`appguardrail_core.github_actions_evidence` is the first source-authoritative evidence acquirer. It does not accept a caller Boolean as detector truth. The production CLI fetches the exact GitHub run and job over a fixed HTTPS origin, rejects redirects and identity mismatch, caps response size, requires completed security-relevant states, rejects future/stale/duplicate evidence, and emits a bounded canonical digest. Raw logs, bearer credentials, and arbitrary cross-repository content are outside this evidence object.

This slice is an acquisition-and-verification contract, not a claim that every historical issue family is directly detected. Each future detector family must supply its own authoritative source, independent oracle, mutation evidence, and production-path proof.

## SSRF architecture

```mermaid
flowchart LR
    INPUT[User-controlled URL]
    VALID[Destination validation]
    STORE[(Stored webhook/callback config)]
    EXEC[Outbound executor]
    DNS[DNS/IP/redirect checks]
    NET[Network request]

    INPUT --> VALID
    VALID --> STORE
    STORE --> EXEC
    EXEC --> DNS
    DNS --> NET
```

Stored SSRF prevention and scanner detection are separate controls. The control-plane write boundary was hardened through PR #924, while PR #910 added the packaged built-in rule `python-stored-ssrf-webhook-url`; both are implemented on protected `develop`. The detector is intentionally bounded to Python `set_webhook` direct and one-hop persistence flows covered by its regression corpus and does not claim universal interprocedural SSRF detection.

## Control-plane boundary

Current standalone control plane is stdlib HTTP + SQLite, with tenant API-key roles and scan/history/drift/webhook configuration. Persistent organization identity is resolved from authenticated key context, not untrusted payload strings. Enterprise replacement of SQLite is behind stable repository service functions and requires migrations/authz/recovery evidence.

## Remediation authority

Autofix can perform only narrowly proven semantics-preserving transformations. Other fixes are guidance for a user/agent and become accepted only after rescanning/reverification. Model-generated remediation is never a substitute for scanner evidence.

## Automation authority

```mermaid
flowchart LR
    DEV[Autonomous developer]
    VERIFY[Tests/security exact-head evidence]
    REVIEW[Independent review agents/humans]
    MERGE[Protected merge]
    RELEASE[Release environment]

    DEV --> VERIFY
    VERIFY --> REVIEW
    REVIEW --> MERGE
    MERGE --> RELEASE
```

The development model does not own qualifying approval, protected merge, release, or reviewer credentials. Scheduler blocks are RCA inputs; one blocked PR does not idle unrelated safe work.

## Deployment modes

1. **CLI/library:** one-shot local scan/report/SBOM/fix.
2. **CI monitor:** installed GitHub workflow generating findings/SARIF and optional control-plane push.
3. **Control plane:** standalone multi-tenant scan history/drift/dashboard/webhook service.
4. **Organization evidence:** read-only aggregation of repository/PR/action evidence for acquisition/security diligence.

These modes share normalized contracts but can operate separately.

## Change control

A new detector engine, evidence acquirer, persistent schema, tenant authority, arbitrary autofix class, outbound target policy, issue-audit semantics, or automation credential boundary requires ADR and synchronized technical/security/test documentation.