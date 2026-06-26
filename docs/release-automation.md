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
- builds the source and wheel distributions;
- checks the distributions with `twine`;
- opens or updates a release PR;
- dispatches the release Security Process workflow.

Central required OpenCode and Strix workflows remain the review gates. The bot
prepares the PR; it does not merge or publish on its own.
