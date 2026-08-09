"""Release, documentation, and automation contracts for issue detection."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class IssueDetectionReleaseContractTests(unittest.TestCase):
    """Keep the executable registry installed, documented, and continuously audited."""

    def test_distribution_includes_registry_and_console_command(self) -> None:
        """Wheel and source distributions retain the runtime registry and CLI."""
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")

        self.assertIn(
            'appguardrail-issue-detection = "appguardrail_core.issue_detection:main"',
            pyproject,
        )
        self.assertIn(
            '"appguardrail_core" = ["issue_detection_registry.json"]',
            pyproject,
        )
        self.assertIn(
            "recursive-include appguardrail_core *.json",
            manifest,
        )

    def test_core_package_declares_public_issue_detection_api(self) -> None:
        """Standalone and MSA consumers receive stable detector entry points."""
        initializer = (ROOT / "appguardrail_core" / "__init__.py").read_text(
            encoding="utf-8"
        )
        expected = {
            "DetectionResult",
            "FamilyAssessment",
            "IssueCoverageAudit",
            "IssueDetectionClaim",
            "IssueDetectionRegistry",
            "IssueDetectionTarget",
            "WorkflowEvidence",
            "WorkflowResultVerifier",
            "audit_issue_coverage",
            "audit_issue_requirements",
            "compute_issue_requirement_sha256",
            "detect_workflow_causes",
            "evaluate_detector_family",
            "evaluate_issue_claim",
            "load_issue_detection_registry",
            "materialize_issue_claim_fixture",
            "registered_detector_families",
        }

        self.assertIn("from appguardrail_core.issue_detection import (", initializer)
        self.assertTrue(all(f'"{name}"' in initializer for name in expected))

    def test_registry_contracts_bind_implementation_and_three_fixtures(self) -> None:
        """Every family declares runtime code and positive/negative/unknown evidence."""
        registry = json.loads(
            (
                ROOT
                / "appguardrail_core"
                / "issue_detection_registry.json"
            ).read_text(encoding="utf-8")
        )

        for contract in registry["detector_families"].values():
            self.assertTrue(contract["no_exclusions"])
            self.assertRegex(
                contract["adapter_ref"],
                r"^appguardrail_core\.issue_detection:_[a-z_]+_adapter$",
            )
            self.assertTrue(contract["implementation_refs"])
            self.assertIn("schema", contract["required_evidence_fields"])
            self.assertTrue(contract["obligations"])
            self.assertEqual(
                len(contract["obligations"]),
                len(
                    {
                        obligation["obligation_id"]
                        for obligation in contract["obligations"]
                    }
                ),
            )
            self.assertEqual(
                set(contract["fixtures"]),
                {"positive", "negative", "unknown"},
            )
            self.assertNotIn(
                '"state"',
                json.dumps(contract["fixtures"], sort_keys=True),
            )

    def test_exact_coverage_workflow_is_read_only_and_pinned(self) -> None:
        """Changed detector behavior always reruns exact focused coverage."""
        workflow = (
            ROOT / ".github" / "workflows" / "issue-detection-coverage.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}", workflow)
        self.assertIn("Require exact event head", workflow)
        self.assertIn("EXPECTED_HEAD_SHA", workflow)
        self.assertIn(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            workflow,
        )
        self.assertIn(
            "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
            workflow,
        )
        self.assertIn("--require-hashes -r requirements-test.txt", workflow)
        self.assertIn("--module appguardrail_core/issue_detection.py", workflow)
        self.assertIn("--module appguardrail_core/issue_detection_docs.py", workflow)
        self.assertIn("name: Issue Classifier and Documentation Contracts", workflow)
        self.assertIn('"requirements-test.txt"', workflow)
        self.assertIn('"scripts/ci/verify_module_coverage.py"', workflow)
        self.assertIn("tests/test_issue_detection.py", workflow)
        self.assertIn("tests/test_issue_detection_documentation.py", workflow)
        self.assertIn("tests/test_issue_detection_release_contract.py", workflow)
        self.assertIn('"docs/issue-detection-traceability.json"', workflow)
        self.assertIn('"docs/adr/**"', workflow)
        self.assertIn('"AGENTS.md"', workflow)
        self.assertIn('"CLAUDE.md"', workflow)
        self.assertIn('"docs/methodology.md"', workflow)
        self.assertIn(
            '"docs/product/2026-07-02-2b-krw-sale-readiness-plan.md"',
            workflow,
        )
        self.assertNotIn("pull_request_target:", workflow)

    def test_live_audit_workflow_is_paginated_and_read_only(self) -> None:
        """Issue lifecycle events are checked against the exact registry set."""
        workflow = (
            ROOT
            / ".github"
            / "workflows"
            / "issue-detection-registry-audit.yml"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "issues:\n    types: [opened, edited, reopened, closed]",
            workflow,
        )
        self.assertIn("schedule:", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("contents: read\n  issues: read", workflow)
        self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}", workflow)
        self.assertIn("Require exact event head", workflow)
        self.assertIn("gh api --paginate --slurp", workflow)
        self.assertIn("state=all&per_page=100", workflow)
        self.assertIn("audit-registry", workflow)
        self.assertIn(
            "Require exact issue inventory and requirement digest reconciliation",
            workflow,
        )
        self.assertNotIn("Require exact issue-to-detector coverage", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("issues: write", workflow)
        self.assertNotIn("secrets.", workflow)

    def test_docs_and_changelog_record_status_aware_fail_closed_contract(self) -> None:
        """Release prose cannot promote inventory accounting to detector efficacy."""
        documentation = (ROOT / "docs" / "issue-detection-contract.md").read_text(
            encoding="utf-8"
        )
        changelog = (
            ROOT / "CHANGELOG.d" / "issue-detection-contract.md"
        ).read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        for phrase in (
            "414",
            "17 classifier families",
            "positive, negative, and unknown",
            "gate_satisfied",
            "does not prove a vulnerability",
            "appguardrail-issue-detection",
        ):
            self.assertIn(phrase, documentation)
        self.assertIn("issue-detection-contract.md", readme)
        self.assertIn("active-PR baseline", readme)
        self.assertIn("issue-detection-traceability.json", readme)
        self.assertTrue(changelog.startswith("### Added\n"))
        self.assertIn("414 issue identities", changelog)
        self.assertIn("direct detector efficacy remains 0/417", changelog)
        self.assertNotIn("all 414", changelog)

    def test_canonical_documentation_graph_is_discoverable_and_state_bearing(self) -> None:
        """The issue-complete contract is reconstructable without chat history."""
        required_documents = {
            "ARCHITECTURE.md": ("## System context", "## Documentation map"),
            "docs/product/PRD.md": ("## Product requirements", "## Delivery status"),
            "docs/engineering/TRD.md": ("## Technical requirements", "## Acceptance evidence"),
            "docs/architecture/UML.md": ("## Component diagram", "## Sequence diagram"),
            "docs/architecture/EVIDENCE_MODEL.md": ("## Conceptual ERD", "## Persistence boundary"),
            "docs/adr/README.md": ("## Decision index", "ADR-0001"),
            "docs/adr/ADR-0001-issue-complete-detection-contract.md": (
                "Status: Accepted",
                "## Consequences",
            ),
            "docs/THREAT_MODEL.md": ("## Trust boundaries", "## Abuse cases"),
            "docs/TEST_STRATEGY.md": ("## Detection-efficacy matrix", "## Mutation sensitivity"),
            "docs/OPERABILITY.md": ("## Service-level objectives", "## Recovery"),
            "docs/INCIDENT_RUNBOOK.md": ("## 1. Contain", "## 5. Close"),
            "docs/TRACEABILITY.md": ("## Requirements matrix", "## Status vocabulary"),
        }

        for relative_path, required_phrases in required_documents.items():
            document_path = ROOT / relative_path
            self.assertTrue(document_path.is_file(), relative_path)
            document = document_path.read_text(encoding="utf-8")
            for phrase in required_phrases:
                self.assertIn(phrase, document, relative_path)

        architecture = (ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        traceability = (ROOT / "docs" / "TRACEABILITY.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("docs/product/PRD.md", architecture)
        self.assertIn("docs/engineering/TRD.md", architecture)
        self.assertIn("ARCHITECTURE.md", readme)
        for state_name in (
            "IMPLEMENTED_ON_PROTECTED_MAIN",
            "ACTIVE_PR",
            "ACCEPTED_TARGET_ARCHITECTURE",
            "PLANNED",
        ):
            self.assertIn(state_name, traceability)

    def test_canonical_docs_do_not_promote_missing_capabilities(self) -> None:
        """Known implementation gaps remain explicit and machine-regressed."""
        architecture = (ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
        prd = (ROOT / "docs" / "product" / "PRD.md").read_text(encoding="utf-8")
        trd = (ROOT / "docs" / "engineering" / "TRD.md").read_text(
            encoding="utf-8"
        )
        evidence_model = (
            ROOT / "docs" / "architecture" / "EVIDENCE_MODEL.md"
        ).read_text(encoding="utf-8")
        traceability = (ROOT / "docs" / "TRACEABILITY.md").read_text(
            encoding="utf-8"
        )
        strategy = (ROOT / "docs" / "TEST_STRATEGY.md").read_text(
            encoding="utf-8"
        )
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        for document in (architecture, prd, trd, traceability):
            self.assertIn("0/417", document)
        self.assertIn("repository/source-artifact identity is not bound", trd)
        self.assertIn("legacy runtime schema", evidence_model.lower())
        self.assertIn("canonical v2 migration schema", evidence_model.lower())
        self.assertIn("Retention and audit evidence are bounded", traceability)
        self.assertIn("`PARTIAL`", traceability)
        self.assertNotIn("statement and branch coverage: exact 100%", strategy)
        self.assertNotIn("appguardrail scan --push http://", readme)

    def test_threat_operations_and_erd_match_as_built_boundaries(self) -> None:
        """Canonical controls and data cardinalities must match executable reality."""
        threat_model = (ROOT / "docs" / "THREAT_MODEL.md").read_text(
            encoding="utf-8"
        )
        operability = (ROOT / "docs" / "OPERABILITY.md").read_text(
            encoding="utf-8"
        )
        evidence_model = (
            ROOT / "docs" / "architecture" / "EVIDENCE_MODEL.md"
        ).read_text(encoding="utf-8")
        evidence_words = " ".join(evidence_model.split())

        self.assertIn("repository/source-artifact binding is `MISSING`", threat_model)
        self.assertIn("independent per-cause aggregation is `MISSING`", threat_model)
        self.assertNotIn(
            "exact producer/run/head/source and digest binding",
            threat_model,
        )
        self.assertIn("## Ownership and escalation", operability)
        self.assertIn("## Operator commands", operability)
        self.assertIn("## Recovery-objective status", operability)
        self.assertIn("does not bind repository or source-artifact identity", operability)
        self.assertIn(
            "composite `(detector_family_id, obligation_id)`",
            evidence_words,
        )
        self.assertIn(
            "composite foreign key `(issue_number, claim_id)`",
            evidence_words,
        )
        self.assertIn(
            "PURGE_PREVIEWS ||--o{ PURGE_RECEIPTS : authorizes",
            evidence_model,
        )

    def test_contributor_and_methodology_docs_preserve_detection_boundary(self) -> None:
        """Repository instructions cannot regress to collector-as-detector claims."""
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        claude = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
        methodology = (ROOT / "docs" / "methodology.md").read_text(
            encoding="utf-8"
        )
        sale_plan = (
            ROOT / "docs" / "product" / "2026-07-02-2b-krw-sale-readiness-plan.md"
        ).read_text(encoding="utf-8")
        agents_words = " ".join(agents.split())

        for document in (agents, claude):
            self.assertIn("collector is not a detector", document)
            self.assertIn("source-bound", document)
            self.assertIn("ACTIVE_PR", document)
        self.assertNotIn("`jules`", agents)
        self.assertNotIn(
            "unless the finding is in docs, tests, examples, or scanner fixtures",
            agents,
        )
        self.assertIn("File location never suppresses a finding", agents_words)
        self.assertIn("human-approved scope and acceptance source", agents_words)
        self.assertIn("not executable evidence", agents_words)
        self.assertIn("exact 100% statement coverage", agents_words)
        self.assertIn("When the target stack uses", claude)
        self.assertIn("PLANNED", methodology)
        self.assertNotIn("| `IMPLEMENTED` |", methodology)
        self.assertIn("IMPLEMENTED_ON_PROTECTED_MAIN", methodology)
        self.assertIn("metadata-only", sale_plan)

    def test_architecture_decisions_are_atomic_indexed_and_status_bearing(self) -> None:
        """Independent authority, outcome, oracle, and persistence choices remain reviewable."""
        adr_root = ROOT / "docs" / "adr"
        index = (adr_root / "README.md").read_text(encoding="utf-8")
        expected = {
            "ADR-0001-issue-complete-detection-contract.md": "no-exclusion",
            "ADR-0002-evidence-authority-and-attestation.md": "source authority",
            "ADR-0003-typed-outcomes-and-gate-aggregation.md": "typed outcomes",
            "ADR-0004-independent-oracles-and-mutation-proof.md": "independent oracle",
            "ADR-0005-control-plane-persistence-migration-boundary.md": (
                "legacy and canonical-v2 persistence"
            ),
        }

        for filename, decision_phrase in expected.items():
            document = (adr_root / filename).read_text(encoding="utf-8")
            adr_id = filename[:8]
            self.assertIn(f"[{adr_id}]({filename})", index)
            self.assertIn("Status: Accepted", document)
            self.assertIn("Implementation:", document)
            self.assertIn(decision_phrase, document.lower())
        umbrella = (adr_root / next(iter(expected))).read_text(encoding="utf-8")
        self.assertIn("ADR-0002", umbrella)
        self.assertIn("ADR-0003", umbrella)
        self.assertIn("ADR-0004", umbrella)

    def test_changelog_and_primary_references_disclose_documentation_limits(self) -> None:
        """Release notes and citations cannot imply retired or unavailable operations."""
        root_changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        retired = (
            ROOT / "CHANGELOG.d" / "856-commercial-readiness-loop.md"
        ).read_text(encoding="utf-8")
        migration = (
            ROOT / "CHANGELOG.d" / "871-retention-schema-migration.md"
        ).read_text(encoding="utf-8")
        issue_fragment = (
            ROOT / "CHANGELOG.d" / "issue-detection-contract.md"
        ).read_text(encoding="utf-8")
        incident = (ROOT / "docs" / "INCIDENT_RUNBOOK.md").read_text(
            encoding="utf-8"
        )
        trd = (ROOT / "docs" / "engineering" / "TRD.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("CHANGELOG.d", root_changelog)
        self.assertIn("unreleased source of truth", root_changelog.lower())
        self.assertIn("Superseded by", retired)
        self.assertIn("OpenCode", retired)
        self.assertIn("migration rehearsal guide", migration)
        self.assertIn("not a production backup/restore runbook", migration)
        self.assertIn("topology/count/declared-status guard", issue_fragment)
        self.assertNotIn("documentation fitness gate", issue_fragment)
        self.assertIn(
            "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
            incident,
        )
        self.assertIn("## References", incident)
        self.assertIn("GitHub. (n.d.)", trd)
        self.assertIn("Retrieved August 9, 2026", trd)


if __name__ == "__main__":
    unittest.main()
