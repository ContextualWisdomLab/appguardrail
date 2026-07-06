# CI integration templates

Ready-to-copy pipeline configs that run AppGuardrail outside GitHub Actions.
(GitHub users already have `appguardrail monitor`, which installs a GitHub
Actions workflow.)

Each template installs AppGuardrail from PyPI, scans the whole checkout, writes
a SARIF 2.1.0 report, and fails the pipeline when AppGuardrail reports
deploy-blocking findings.

## GitLab CI

Copy [`gitlab-ci.yml`](./gitlab-ci.yml) to your repository root as
`.gitlab-ci.yml` (or merge the `appguardrail` job into your existing pipeline).
The SARIF report is saved as a build artifact (`appguardrail.sarif`).

## CircleCI

Copy [`circleci-config.yml`](./circleci-config.yml) to your repository as
`.circleci/config.yml` (or merge the `security-scan` job and `security`
workflow into your existing config). The SARIF report is stored as a job
artifact (`appguardrail.sarif`).

## What runs

Both templates run:

```bash
python -m scanner.cli.appguardrail scan --sarif appguardrail.sarif .
```

## What makes the pipeline fail

`scan` exits non-zero when it finds **deploy-blocking** findings (CRITICAL and
HIGH severity by default). CI treats a non-zero exit as a failed job, so the
pipeline goes red. A clean scan exits `0` and the pipeline passes. The SARIF
report is written in both cases.

To tune which severities block the gate (or to suppress specific rule ids), add
an optional `.appguardrail.json` to your repository — see the main
[README](../README.md) for details.
