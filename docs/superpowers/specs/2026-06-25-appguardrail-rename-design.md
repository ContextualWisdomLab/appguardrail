# AppGuardrail Rename Design

## Status

Approved direction: full rename from VibeSec to AppGuardrail.

This design documents the rename before implementation. The goal is to remove the PyPI namespace collision risk caused by the existing `vibesec` package name and to align every public install, command, workflow, and documentation surface around one canonical identity.

## Problem

The public project currently presents itself as `VibeSec` and documents `pip install vibesec`. The `vibesec` PyPI project is already occupied by a different maintainer and points at a different GitHub repository. For a security tool, that creates a critical supply-chain and user trust problem: a user following the README can install a package that is not produced by this repository.

The rename must solve the trust problem, not only the marketing problem. Keeping `VibeSec` as the product name while publishing a differently named package would leave a persistent ambiguity between the README, CLI, package metadata, SARIF category, workflow artifacts, and external references.

## Decision

Use `AppGuardrail` as the canonical product name.

Canonical identifiers:

- Product name: `AppGuardrail`
- PyPI distribution name: `appguardrail`
- CLI command: `appguardrail`
- Python module name: `appguardrail`
- GitHub repository name: `ContextualWisdomLab/appguardrail`
- GitHub Action workflow names and artifacts: `appguardrail-*`
- SARIF category: `appguardrail`
- Generated rule file names: `appguardrail.md`
- Ignore file, if present later: `.appguardrailignore`

Temporary migration wording may say "formerly developed as VibeSec" for one or two releases, but new user-facing examples must use only `AppGuardrail` and `appguardrail`.

## Naming Rationale

`AppGuardrail` keeps the strongest part of the current positioning: security guardrails for AI-built applications. It avoids the occupied `vibesec` namespace and avoids making the product depend on the overloaded `vibe` term.

Rejected alternatives:

- `cwl-vibesec`: acceptable as an emergency package name, but it keeps the confusing `VibeSec` identity and does not fully solve user trust.
- `ScaffoldSec`: narrower than the current product direction because it sounds focused on generated scaffolds rather than the full coding, deploy, monitoring, and fix loop.
- `AI Code Guard`: clear but generic and harder to own as a compact CLI/package identity.

## Product Scope

The rename preserves the current product direction:

- AI-built app security guardrails
- Local static scan for secrets, auth gaps, misconfigurations, and risky app patterns
- Optional Trivy-backed vulnerability, secret, and misconfiguration scan
- Review and fix prompts for AI coding assistants
- Responsible use and authorization guidance
- CI deploy gate output and future machine-readable results

The rename does not change scanner semantics, finding severity policy, or the responsible testing boundary.

## Implementation Scope

The implementation should update all first-party references in one branch:

- README title, badges, Quick Start, CLI examples, repository structure, services table, and Korean summary text
- `docs/` methodology, responsible testing, scope and authorization, and security snapshot planning documents
- `scanner/cli/vibesec.py` renamed or wrapped as `scanner/cli/appguardrail.py`
- CLI help text, `argparse` program name, version output, pre-commit hook text, generated rule/checklist text, verification commands, and repository URLs
- generated Cursor/Windsurf rule filenames from `vibesec.md` to `appguardrail.md`
- workflows, job names, artifact names, scan output filenames, and check labels that currently say `VibeSec` or `vibesec`
- tests and fixtures that assert CLI output, file names, help text, or generated paths
- changelog entry documenting the rename and migration

If packaging metadata is introduced in the same change, it must publish `appguardrail`, not `vibesec`.

## Compatibility Policy

The first implementation should favor trust clarity over long compatibility.

Required compatibility behavior:

- `appguardrail` is the only documented install and command.
- The scanner output tells users to rerun `appguardrail scan`, not `vibesec scan`.
- Generated project files use `appguardrail.md`.
- CI examples install from the repository or from `appguardrail` once the PyPI project is owned.

Optional short-term compatibility:

- Keep a deprecated `vibesec` command only if packaging already exposes it and only if it prints a deprecation warning that points to `appguardrail`.
- Do not continue documenting `pip install vibesec`.

## Supply-Chain Requirements

Before publishing a package:

- Reserve or create the `appguardrail` PyPI project under the official maintainer account.
- Set PyPI project metadata to the canonical GitHub repository.
- Use Trusted Publishing from GitHub Actions.
- Build from signed or protected release tags.
- Publish wheel and sdist hashes in the release notes.
- Keep GitHub Release version and PyPI version aligned.
- Add a release checklist that verifies `pip install appguardrail`, `pip show appguardrail`, `appguardrail --version`, and package metadata.

Until those controls are ready, documentation should prefer installation from a pinned signed tag or a local checkout, not PyPI.

## Validation

The implementation is complete when:

- `rg -n "VibeSec|vibesec" README.md docs scanner tests .github checklists prompts reports examples scripts CHANGELOG.md` returns only intentional historical migration notes.
- `python3 scanner/cli/appguardrail.py --help` shows `appguardrail`.
- `python3 scanner/cli/appguardrail.py scan .` runs successfully.
- Existing focused tests pass after renaming expectations.
- The security workflow no longer uploads artifacts named `vibesec-*`.
- The README no longer contains `pip install vibesec`.
- The public install path cannot direct users to the third-party PyPI `vibesec` project.

## Rollout Plan

1. Land the repository rename and internal identifier change on a normal PR.
2. Update GitHub repository name to `appguardrail` after the code PR is ready or immediately after merge.
3. Create a short migration note in `CHANGELOG.md` and README.
4. Reserve the PyPI `appguardrail` project and configure Trusted Publishing before any public package release.
5. Publish the first AppGuardrail release only after install provenance is verified.

## Non-Goals

- Rewriting scanner rules or severity policy.
- Adding a dashboard or hosted service.
- Expanding dynamic testing scope.
- Keeping `VibeSec` as a long-term alias.
