# AppGuardrail Release Automation

This repository has two release workflows:

- `Prepare PyPI Release`: creates a release PR with GitHub Actions Bot.
- `Publish Python Package`: publishes an already-merged version to PyPI through Trusted Publishing.

## Recommended Beginner Flow

1. Open GitHub Actions.
2. Run `Prepare PyPI Release`.
3. Enter the next version, for example `0.1.2`.
4. Review the generated PR.
5. Wait for central required OpenCode and Strix checks plus Security Process evidence.
6. Merge the release PR.
7. Run `Publish Python Package` from `develop`, or push the matching `vX.Y.Z` tag while that release commit is still the exact current `develop` tip.

The prepare workflow refuses to create a release if that version already exists on
PyPI. This prevents accidental duplicate uploads.

## Protected-source release gate

`Publish Python Package` fails closed before installing release tooling unless the
checked-out `GITHUB_SHA` is the exact current `develop` tip fetched from the
repository. For a manual run, `GITHUB_REF` must also be `refs/heads/develop`.
For a tag-triggered run, the tag must be exactly `v<package-version>` and point to
that same current protected tip.

This is intentionally stricter than GitHub Actions' default manual-dispatch
behavior. GitHub allows an operator with write access to select another branch
when manually running a `workflow_dispatch` workflow. AppGuardrail does not let
that branch selection expand the PyPI Trusted Publisher boundary: a manual
dispatch from another branch is rejected, as is a tag/version mismatch or a tag
whose commit is no longer the current protected release head.

After `python -m build` and `twine check`, the workflow installs the built wheel
with `--no-deps` into a fresh virtual environment, changes directory outside the
source checkout, executes the installed `appguardrail --version` entry point,
and verifies that packaged scanner rules and dashboard assets are present. The
publish job therefore receives only an artifact that has passed both metadata
checks and a black-box installed-wheel smoke test.

PyPI Trusted Publishing removes long-lived upload credentials but does not prove
that source code is safe or that a workflow was invoked from the intended source
revision. PyPI explicitly treats the trusted publishing workflow and the actors
who can change or invoke it as part of the security boundary. AppGuardrail's
protected-source gate narrows that invocation boundary; PyPI's default digital
attestations remain complementary artifact-origin evidence rather than a
substitute for source-selection policy.

## Scanner release-source policy rule

`github-actions-pypi-unbound-release-source` is a HIGH source-policy warning.
It recognizes ordinary block YAML with two-space job indentation, six-space
step indentation, `workflow_dispatch` (scalar or block) or block `push.tags`,
local `python -m build` / `python3 -m build` run steps, and
`pypa/gh-action-pypi-publish@` action steps in the same job or scalar/inline-list
`needs` descendants. Every reachable local build must have its own gate;
sibling-job text, comments, echo-only evidence and gates after a build do not
donate proof. The publisher action line identifies the finding.

Single/double-quoted `push` / `tags`, `uses`, `ref`, `repository`, step `if` /
`continue-on-error` / `shell` and job `continue-on-error` keys retain the
same sink/source/enforcement semantics.
Only these supported block keys (plus `on` / `workflow_dispatch` / `with`)
normalize optional quotes and whitespace before the mapping colon. Publisher
action-name matching is case-insensitive; no case-sensitive admission filter
can skip that sink.
Enforcement metadata is checked both as the first step key and as subsequent
step fields. A shallow same-line check also rejects checkout `with: {...}`
containing `ref` or `repository` keys; this is not general flow-YAML parsing.

The recognized negative oracle is the reviewed #967 gate: default
`actions/checkout` source; an unconditional pre-build shell block beginning
with `set -euo pipefail`, successful `git fetch --no-tags origin develop`,
`protected_sha="$(git rev-parse origin/develop)"`, and a mismatch check of
`GITHUB_SHA` that emits an error and exits 1. Conditional/custom-shell or
continue-on-error steps, job-level continue-on-error, alternate checkout refs
or repository overrides, and a subsequent checkout invalidate that proof.
This detector checks protected commit binding, not the separate version/tag
policy or wheel smoke acceptance.

False-positive boundary: equivalent custom shell gates, protected branches
other than `develop`, reviewed immutable release policies, conditional
publisher restrictions and externally enforced environment policies can warn.
Review those policies; do not infer that the publisher is exploitable solely
from this result. False-negative boundary: YAML anchors/aliases, alternate
indentation, flow-style jobs/events, multiline `needs`, reusable workflows,
custom/composite build or upload actions, alternate build commands and dynamic
artifact/source selection are not analyzed. The matcher follows job
dependencies, not a complete artifact or shell control-flow graph; a gate does
not prove absence of later source modification.

The source evidence is copied byte-for-byte into
`tests/fixtures/release_source/`: protected vulnerable workflow at
`2949d30718752ea5915c7713ba227e8c19d9e5bf` (blob
`20af591a18d4de1c379d7e6c128a4e7b8673966f`) and #967 fixed workflow at
`5a48b748cb68a9f429f1740f7e864aa29add7b34` (blob
`1961a5a31deb2db3b96acb4101332cef0029aad3`).
`tests/test_release_source_detector.py` exercises the real packaged scanner
with both oracles and enforcing/dominance/authority near-miss boundaries,
including inert trigger comments and other-repository source checkout.
No workflow was dispatched and no external PyPI upload acceptance is claimed.

## What the Bot Automates

The GitHub Actions Bot:

- validates that the requested version is not already on PyPI;
- updates `scanner/cli/appguardrail.py`;
- adds a changelog entry;
- installs release build tooling from `requirements-release.txt` with
  `pip --require-hashes`;
- audits the installed release build tooling environment with `pip-audit`
  against OSV data;
- builds the source and wheel distributions;
- checks the distributions with `twine`;
- uploads `release-sbom.cdx.json` and `release-provenance.json` as the
  `release-supply-chain-evidence` artifact;
- opens or updates a release PR;
- dispatches the release Security Process workflow.

Central required OpenCode and Strix workflows remain the review gates. The bot
prepares the PR; it does not merge or publish on its own.

## Release Dependency Lock

`requirements-release.in` lists the direct release build tools. Regenerate
`requirements-release.txt` with hashes after changing it:

```bash
uv pip compile --generate-hashes --python-version 3.13 --universal requirements-release.in -o requirements-release.txt
```

The prepare and publish workflows install release build tooling only with
`pip install --require-hashes`. This keeps build, upload, SBOM, and audit tools
bound to the hashes reviewed in the repository.

## Release Evidence

Both release workflows create a CycloneDX environment SBOM and a provenance JSON
file that records the workflow identity, commit, Python runtime, hashed release
requirements file, and SHA-256 digests for the built distributions.

The publish workflow uses PyPI Trusted Publishing through
`pypa/gh-action-pypi-publish`, so the package upload job keeps `id-token: write`
isolated to the publishing step. That action publishes digital attestations by
default for Trusted Publishing flows.

## References (APA 7th)

GitHub Docs. (2026). *Manually running a workflow*. GitHub. https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow

GitHub Docs. (2026). *Events that trigger workflows*. GitHub. https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows

Python Packaging Authority. (2026). *Security model and considerations*. PyPI Docs. https://docs.pypi.org/trusted-publishers/security-model/

Python Packaging Authority. (2026). *Producing attestations*. PyPI Docs. https://docs.pypi.org/attestations/producing-attestations/
