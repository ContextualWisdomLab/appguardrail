# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

AppGuardrail (formerly VibeSec) is a security guardrail toolkit for AI-built apps: a zero-dependency Python CLI that installs security rules for AI coding tools, statically scans codebases for AI-coding failure modes (hardcoded secrets, missing authz, Supabase/Firebase misconfig, unverified Stripe webhooks), and turns findings into reports, SARIF, SBOMs, dashboards, and a control-plane scan history. Published to PyPI as `appguardrail`. Default branch is `develop`; release PRs and tags are cut from it.

## Commands

```bash
# Run the full test suite (pytest is the only test dependency; no install of
# the package needed — pytest.ini sets pythonpath = .)
python3 -m pytest

# Run one file / one test
python3 -m pytest tests/test_sarif.py
python3 -m pytest tests/test_findings_core.py::test_name -v

# Run the CLI from source (exactly how CI invokes it)
python3 scanner/cli/appguardrail.py --help
python3 scanner/cli/appguardrail.py scan .

# Self-scan deploy gate as run by .github/workflows/security-process.yml
python3 scanner/cli/appguardrail.py scan --codegraph .

# Build distributions (release tooling pinned in requirements-release.txt)
python -m build && python -m twine check dist/*
```

There is no lint/format tool configured. `[tool.interrogate]` in `pyproject.toml` tracks docstring coverage (tests excluded), so keep docstrings on public functions.

## Hard constraints

- **Zero runtime dependencies.** `pyproject.toml` declares `dependencies = []` and the code is stdlib-only (`sqlite3`, `http.server`, `re`, `json`, ...). YAML rule files and lockfiles are parsed by hand-rolled stdlib parsers — do not add PyYAML, requests, etc.
- **Python >= 3.9** compatibility.
- **CI runs the tool on itself.** Every push/PR to `develop`/`main` triggers the Security Process workflow: `scan --codegraph .` as a deploy gate plus a Trivy FS scan that fails on CRITICAL/HIGH. Findings in `docs/`, `tests/`, `examples/`, and scanner rule fixtures are non-blocking contexts, so vulnerable test fixtures belong there — anything that looks like a real secret or vuln in app code will fail CI.
- Tests aim for exhaustive coverage of `scanner/cli/appguardrail.py` (100% per CHANGELOG); new CLI behavior needs matching tests in `tests/`.

## Architecture

Two Python packages ship in the wheel (`scanner*`, `appguardrail_core*`); everything else is packaged content or CI tooling.

- **`scanner/cli/appguardrail.py`** — the entire CLI in one file (~3.6k lines); console script `appguardrail` maps to its `main()`. Subcommands: `init`, `scan`, `fix`, `review`, `report`, `org-bundle`, `monitor`, `hook`, `serve`, `sbom`, `dashboard`. It owns file traversal, the built-in `SCAN_RULES` list (pre-compiled regexes), output printing, and argparse wiring, and delegates shared logic to `appguardrail_core`. `__version__` lives here — `pyproject.toml` reads it dynamically, so release version bumps edit this file plus `CHANGELOG.md`.
- **`appguardrail_core/`** — reusable stdlib-only library:
  - `findings.py` — the normalized finding contract (`appguardrail.findings.v1` envelope) shared by every surface. Severities are `CRITICAL/HIGH/WARNING/INFO`; the deploy gate blocks CRITICAL+HIGH; contexts `doc/test/example/scanner-fixture` never block.
  - `config.py` — optional repo-level `.appguardrail.json` (`fail_on`, `exclude_rules`) that tunes the gate; invalid config fails loudly.
  - `rules.py` — `RuleMetadata` enrichment (OWASP/CWE/SAMM references, remediation) derived from rule messages and categories.
  - `external.py` — plans which optional external engines (Trivy, Bandit, Ruff, Semgrep, ZAP) run, based on availability and `language.py` stack detection. They are subprocess integrations, never dependencies.
  - `sarif.py`, `sbom.py`, `reports.py`, `autofix.py` — SARIF 2.1.0 export, CycloneDX 1.5 SBOM from hand-parsed lockfiles, markdown report renderers (HTML-escaped prose, secrets redacted), and safe purely-additive auto-fixes.
  - `controlplane.py` — the `serve` backend: multi-tenant scan-history API (sqlite3 + http.server) with Bearer-key auth, viewer/member/owner RBAC, drift detection, and Slack-aware webhooks.
  - `issueops.py`, `org_intelligence.py`, `org_bundle.py`, `metrics.py` — org-level readiness/buyer-evidence reporting used by `org-bundle` and the `scripts/ci/` collectors.
- **Data flow of a scan:** collect files (symlink-safe, size-capped, `SKIP_DIRS`) → built-in regex rules + packaged YAML rules + optional external engines → `normalize_findings` → deploy gate (severity + context + `.appguardrail.json`) → sinks: terminal, `--findings-json`, `--sarif`, `--push <control-plane>`. The findings JSON is the interchange format consumed by `report`, `dashboard` (static page in `scanner/dashboard/`), and the control plane.
- **Packaged content** (MANIFEST.in / package-data): `rules/` (per-tool rule docs that `appguardrail init` copies into user projects for Cursor/Claude Code/Windsurf/Lovable), `checklists/` (stack-specific markdown checklists), `prompts/` (paste-into-AI review/fix prompts), `reports/templates/`, `scanner/rules/*.yml`, `scanner/dashboard/*.html`.
- **`scripts/ci/`** — org security IssueOps scripts run by `.github/workflows/org-security-failure-collector.yml`; they are covered by tests in `tests/`.

## Scanner rule conventions

- YAML rules in `scanner/rules/*.yml` use a Semgrep-like shape (`id`, `patterns`, `message`, `severity`, `languages`), but **only `pattern-regex` entries are executed** by the lightweight engine; structural `pattern:` entries are documented fixtures. The loader (`_load_packaged_regex_rules`) parses the YAML by hand — keep new rules to the existing field shapes.
- Use non-capturing groups `(?:...)` in rule regexes (ReDoS/perf), anchor patterns to their stack's real syntax to avoid false positives on look-alike files, and include an OWASP/CWE reference in the message (e.g. `[OWASP A03:2021 - Injection]`) — `rules.py` extracts these into report metadata.
- Every new rule needs positive + negative pattern tests (see `tests/test_cloudformation_rules.py` for the expected style: per-rule fire/no-fire, severity assertions, end-to-end scan on tainted vs. safe fixtures).
- The scan hot path (`_collect_files`, `_scan_file`) has been repeatedly hardened: never follow symlinks, cap file size (~10MB), sanitize untrusted text before terminal output, and prefer plain string ops over `pathlib` methods inside loops. Preserve these properties when touching it.

## Releases and PRs

- Releases are automated via GitHub Actions (`docs/release-automation.md`): `Prepare PyPI Release` (workflow_dispatch, opens a release PR against `develop` that bumps `__version__` and the changelog) → merge → `Publish Python Package` (Trusted Publishing on `v*` tags, with pip-audit, SBOM, and provenance evidence).
- PR merge gates are robot reviews (CodeRabbit) plus central required OpenCode/Strix checks and the Security Process workflow — see `.agents/skills/github-robot-review-gate/SKILL.md` before fighting a blocked merge. Do not bypass branch protection or dismiss checks.
- `CHANGELOG.md` is written in Korean (with English technical terms inline); follow that convention when adding entries. README is bilingual English/Korean.
