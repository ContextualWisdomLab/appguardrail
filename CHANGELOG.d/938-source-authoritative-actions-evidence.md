## Added

- Added `appguardrail-actions-evidence`, a source-authoritative GitHub Actions verifier that acquires exact workflow-run and workflow-job objects from the pinned GitHub REST API instead of accepting a caller-provided pass/fail assertion.
- Added immutable `ActionsJobEvidence` output with repository, run, job, commit, terminal outcome, failed-step, freshness, probe/acquirer, and SHA-256 source identity.
- Added fail-closed validation for wrong-origin URLs, identifier mismatch, malformed SHA/timestamps, incomplete states, non-security jobs, future or stale evidence, duplicates, oversized/non-JSON responses, and unavailable source data.
- Added a dedicated exact-head statement/branch coverage and complete-docstring workflow, with Coverage.py 7.15.4 pinned to verified source commit `4c0e7ff425ecbb33e2b994b41118a71eb4e39021`.
- Added ADR-0007, architecture integration, buyer/operator runbook, threat controls, PII-preserving alternatives, requirement traceability, and APA 7th references.

## Security

- GitHub API acquisition is fixed to `https://api.github.com`, rejects redirects, caps responses at 2 MiB, emits sanitized errors, and excludes bearer tokens and raw logs from portable evidence.
- Invalid or unavailable evidence returns an explicit inconclusive exit path instead of being interpreted as success.