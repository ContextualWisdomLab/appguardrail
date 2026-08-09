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
        self.assertIn("tests/test_issue_detection.py", workflow)
        self.assertIn("tests/test_issue_detection_release_contract.py", workflow)
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
        self.assertIn("gh api --paginate --slurp", workflow)
        self.assertIn("state=all&per_page=100", workflow)
        self.assertIn("audit-registry", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("issues: write", workflow)
        self.assertNotIn("secrets.", workflow)

    def test_docs_and_changelog_record_fail_closed_contract(self) -> None:
        """Maintainers can map new issues without confusing failures with findings."""
        documentation = (ROOT / "docs" / "issue-detection-contract.md").read_text(
            encoding="utf-8"
        )
        changelog = (
            ROOT / "CHANGELOG.d" / "issue-detection-contract.md"
        ).read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        for phrase in (
            "414",
            "17 detector families",
            "positive, negative, and unknown",
            "gate_satisfied",
            "does not prove a vulnerability",
            "appguardrail-issue-detection",
        ):
            self.assertIn(phrase, documentation)
        self.assertIn("issue-detection-contract.md", readme)
        self.assertTrue(changelog.startswith("### Added\n"))
        self.assertIn("all 414", changelog)

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


if __name__ == "__main__":
    unittest.main()
