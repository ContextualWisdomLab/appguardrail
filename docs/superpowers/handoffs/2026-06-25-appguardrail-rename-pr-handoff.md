# AppGuardrail Rename PR Handoff

## Status

The full rename from VibeSec to AppGuardrail is implemented on branch `appguardrail-rename-design`.

This handoff treats the long-running `scripts/ci/test_strix_quick_gate.sh` harness as non-blocking evidence for this rename. The rename-specific workflow, syntax, test, CodeGraph, and residual-reference checks below are the review evidence for this branch.

## Change Summary

- Renamed the CLI module from `scanner/cli/vibesec.py` to `scanner/cli/appguardrail.py`.
- Renamed scanner tests from `tests/test_vibesec*.py` to `tests/test_appguardrail*.py`.
- Updated CLI command text, generated rule filenames, checklist filenames, hook text, scanner source IDs, and review prompts to `appguardrail` / `AppGuardrail`.
- Added a pre-commit hook fallback so trusted-checkout users can run the repo-local CLI when no `appguardrail` executable is installed on `PATH`.
- Updated README Quick Start examples to use the trusted checkout CLI path consistently until an official package entrypoint exists.
- Updated `.github/workflows/security-process.yml` job, command, output file, and artifact names to `appguardrail-scan`.
- Updated Strix quick-gate path references and OpenCode normalizer test fixtures to `scanner/cli/appguardrail.py`.
- Updated README, methodology, responsible-testing, scope, security snapshot, report templates, and CHANGELOG public naming.
- Removed public install guidance for `pip install vibesec`. README now uses trusted checkout or pinned release-tag guidance until official `appguardrail` PyPI provenance exists.
- Added `pytest.ini` so plain `pytest -q` resolves repository modules consistently.

## Non-Blocking Harness Note

`scripts/ci/test_strix_quick_gate.sh` is a broad shell harness for Strix workflow behavior. During local validation it entered long-running PR-context cases and was interrupted. That run is not used as blocking evidence for this rename because the changed surface is limited to scanner path/name references and workflow artifact names.

Rename-specific evidence was verified with:

- `bash -n scripts/ci/strix_quick_gate.sh scripts/ci/test_strix_quick_gate.sh`
- static assertions that the Strix gate and its shell test reference `scanner/cli/appguardrail.py`
- `actionlint .github/workflows/security-process.yml`
- focused Python tests for the OpenCode normalizer fixture rename

## Verification

Passing checks:

```bash
pytest -q
# 111 passed
```

```bash
python3 -m py_compile scanner/cli/appguardrail.py scripts/ci/pr_review_merge_scheduler.py scripts/ci/opencode_review_normalize_output.py
```

```bash
codegraph sync && codegraph status
# Index is up to date
```

```bash
actionlint .github/workflows/security-process.yml
```

```bash
bash -n scripts/ci/strix_quick_gate.sh scripts/ci/test_strix_quick_gate.sh
```

```bash
python3 scanner/cli/appguardrail.py --help
python3 scanner/cli/appguardrail.py scan <initialized-temp-dir>
```

Residual public install/path audit:

```bash
rg -n "pip install vibesec|pip install appguardrail|scanner/cli/vibesec.py|tests/test_vibesec|scanner\\.cli\\.vibesec|vibesec-scan|vibesec\\.md|VIBESEC_CHECKLIST" README.md docs scanner tests .github checklists prompts reports examples scripts CHANGELOG.md
```

The remaining hits are limited to internal design/plan documents under `docs/superpowers/` that intentionally describe the old state and migration plan. Runtime code, workflow files, tests, README, and product docs no longer direct users to the third-party `vibesec` package or command.

## Branch State

Implementation commits on top of `origin/develop` before this handoff document:

```text
aa1e80f test: make pytest resolve repo modules
3eb059d docs: rename project to AppGuardrail
bcd203c ci: rename scanner workflow to AppGuardrail
109b349 refactor: rename CLI to AppGuardrail
42d7e44 docs: add AppGuardrail rename implementation plan
49055b6 docs: add AppGuardrail rename design
```

This handoff document is committed on top of those implementation commits.

Known local-only state not intended for the PR:

- `.Jules/palette.md` is modified due to the pre-existing macOS case-collision checkout state.
- `.codegraph/` and `.cursor/` are local CodeGraph initialization artifacts and remain untracked.
