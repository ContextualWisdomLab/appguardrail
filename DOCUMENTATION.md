# AppGuardrail Documentation Map

AppGuardrail has extensive rule, scanner, report, release, issue, and scheduler documentation. This index establishes the cross-cutting product and architecture graph so buyers and maintainers do not have to reconstruct the product from README, workflows, issue bodies, and feature-specific notes.

| Area | Canonical document |
|---|---|
| Product requirements | [`docs/PRD.md`](docs/PRD.md) |
| Technical requirements | [`docs/TRD.md`](docs/TRD.md) |
| Architecture | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| UML/runtime/detection flows | [`docs/UML.md`](docs/UML.md) |
| Logical/physical data model | [`docs/ERD.md`](docs/ERD.md) |
| Threat model | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) |
| Test and detector-validation strategy | [`docs/TEST_STRATEGY.md`](docs/TEST_STRATEGY.md) |
| Operability/recovery/release | [`docs/OPERABILITY.md`](docs/OPERABILITY.md) |
| Detection/issue/evidence traceability | [`docs/TRACEABILITY.md`](docs/TRACEABILITY.md) |
| Architecture decisions | [`docs/adr/README.md`](docs/adr/README.md) |
| Security reporting | [`SECURITY.md`](SECURITY.md) |
| Release automation | [`docs/release-automation.md`](docs/release-automation.md) |
| Productization roadmap | [`docs/product/2026-07-02-2b-krw-sale-readiness-plan.md`](docs/product/2026-07-02-2b-krw-sale-readiness-plan.md) |
| Agent development rules | [`AGENTS.md`](AGENTS.md) |
| Agent context | [`CLAUDE.md`](CLAUDE.md) |
| Product overview | [`README.md`](README.md) |
| Change history | [`CHANGELOG.md`](CHANGELOG.md) |

## Maturity vocabulary

- **implemented-main** — source and tests exist on protected `develop`.
- **active-PR** — implementation/evidence exists only on an open pull request.
- **planned** — accepted product target without executable detector/control yet.
- **external-engine** — capability delegated to an optional scanner such as Semgrep/Trivy/Bandit/ZAP rather than AppGuardrail's lightweight built-in matcher.
- **evidence-only** — information visible in reports/history but not yet executable as an AppGuardrail detector.

Critical current distinction: PR #911's no-exclusions issue-to-detector registry and executable obligation coverage remain **active-PR**, not protected-branch behavior. Stored-webhook SSRF prevention from PR #924 and bounded built-in detection from PR #910 are **implemented-main** as separate controls; the packaged rule covers its tested Python `set_webhook` persistence patterns and is not a universal SSRF taint-analysis claim.