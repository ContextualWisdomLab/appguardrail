# AGENTS.md

Cross-agent conventions for the **appguardrail** repo. Any coding agent
(Claude, Codex, Cursor, opencode, …) should read this before working here.
AppGuardrail is a pure-Python package/CLI (`pyproject.toml`,
`requirements-release.txt`, published to PyPI) — there is no Dockerfile or
k8s manifest in this repo today.

<!-- BEGIN cwl-agent-guidance -->
## Agent guidance (CWL governance)

### Security & review gate
- Every PR must pass the central **Security Scan** required gate: `osv-scan` +
  `dependency-review` (diff-scoped) and `trivy-fs` (repo-wide, CRITICAL/HIGH,
  fixable only). It runs on every PR base, **including stacked PRs**. This repo
  also wires `trivy-fs` locally in `.github/workflows/security-process.yml`
  (`scan-type: fs`, `severity: CRITICAL,HIGH`, `ignore-unfixed: true`).
- **A failing `trivy-fs` is a REAL finding, not a flake.** Read the job log — it
  prints each finding's rule id / severity / file — or open the run's SARIF
  (`trivy-results.sarif`) results. Then **remediate**:
  - Vulnerable dependency (the common case here, since the package is pure
    Python): bump the pin in `requirements-release.txt` / `pyproject.toml`.
  - Misconfig: fix it at the source. Worked example — **DS-0026 (Dockerfile
    missing `HEALTHCHECK`)** reads as rule `DS-0026` / severity / the offending
    file, and is fixed by adding a `HEALTHCHECK` instruction. (This repo ships
    no Dockerfile yet; if one is added, this is the finding to expect.)
  - Genuine false positive only: add a narrow, **documented** `.trivyignore`
    (or `.trivyignore.yaml`) entry — one CVE/rule id with a comment saying why.
- **Do NOT weaken or disable the gate.** A local scan with a stale DB misses
  findings: run `trivy --download-db-only` first, and scan the merge ref, not
  just the PR head.
- The org `code_scanning` ruleset is intentionally **CodeQL-only** (multiple
  code-scanning tools can't converge on one PR ref). Gating is by the Security
  Scan **job result**, not the `code_scanning` rule — do **not** add tools to
  that rule.

### Code exploration
- No `.codegraph/` index is committed here, so use normal search (grep/find,
  your editor's symbol tools) to locate and understand code. If a `.codegraph/`
  index is ever added at the repo root, prefer CodeGraph
  (`codegraph explore "<query>"`, or the code-review-graph MCP tools) **before**
  grep/find — it surfaces callers/callees/impact that text search misses.
<!-- END cwl-agent-guidance -->
