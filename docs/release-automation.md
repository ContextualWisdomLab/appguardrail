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
7. Run `Publish Python Package` from `develop`, or push the matching `vX.Y.Z` tag.

The prepare workflow refuses to create a release if that version already exists on
PyPI. This prevents accidental duplicate uploads.

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
