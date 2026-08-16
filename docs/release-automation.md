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
