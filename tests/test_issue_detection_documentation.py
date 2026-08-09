"""Behavioral tests for the issue-detection documentation fitness gate."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "appguardrail_core" / "issue_detection_docs.py"
MODULE_SPEC = importlib.util.spec_from_file_location(
    "appguardrail_issue_detection_docs_under_test",
    MODULE_PATH,
)
if MODULE_SPEC is None or MODULE_SPEC.loader is None:
    raise RuntimeError("unable to load issue-detection documentation validator")
issue_detection_docs = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = issue_detection_docs
MODULE_SPEC.loader.exec_module(issue_detection_docs)


MANIFEST_PATH = ROOT / "docs" / "issue-detection-traceability.json"


def _copy_contract_tree(destination: Path) -> Path:
    """Copy the manifest and every declared artifact into an isolated tree."""
    payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    target_manifest = destination / "docs" / MANIFEST_PATH.name
    target_manifest.parent.mkdir(parents=True)
    target_manifest.write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )
    registry = ROOT / payload["registry_path"]
    registry_target = destination / payload["registry_path"]
    registry_target.parent.mkdir(parents=True, exist_ok=True)
    registry_target.write_bytes(registry.read_bytes())
    for artifact in payload["artifacts"]:
        source = ROOT / artifact["path"]
        target = destination / artifact["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    return target_manifest


class DocumentationContractTests(unittest.TestCase):
    """Prove documentation status is complete, linked, and never overstated."""

    def test_repository_manifest_resolves_current_artifacts_and_diagrams(self) -> None:
        """A maintainer receives one validated, status-aware documentation graph."""
        audit = issue_detection_docs.audit_issue_detection_documentation(
            ROOT,
            MANIFEST_PATH,
        )

        self.assertEqual(audit.artifact_count, 11)
        self.assertEqual(audit.issue_count, 414)
        self.assertEqual(audit.claim_count, 417)
        self.assertEqual(audit.detector_family_count, 17)
        self.assertEqual(audit.cause_bound_issue_count, 0)
        self.assertEqual(audit.direct_detector_efficacy_validated_claim_count, 0)
        self.assertEqual(audit.protected_main_operational_issue_count, 0)
        self.assertEqual(audit.unique_claim_semantics_count, 20)
        self.assertEqual(
            audit.capability_states,
            {
                "family_adapter_coverage": "active_pr",
                "inventory_coverage": "active_pr",
                "per_issue_cause_binding": "missing",
                "protected_main_operational_proof": "missing",
                "source_result_instrumentation": "partial",
            },
        )
        self.assertEqual(
            set(audit.diagram_kinds),
            {"erDiagram", "flowchart", "sequenceDiagram", "stateDiagram"},
        )

    def test_missing_declared_artifact_fails_closed(self) -> None:
        """A stale manifest cannot pass after one canonical document disappears."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _copy_contract_tree(root)
            (root / "docs" / "product" / "PRD.md").unlink()

            with self.assertRaisesRegex(
                ValueError,
                r"declared documentation artifact does not exist: docs/product/PRD\.md",
            ):
                issue_detection_docs.audit_issue_detection_documentation(root, manifest)

    def test_completion_claim_requires_protected_main_operational_proof(self) -> None:
        """A registry cannot be promoted to shipped issue-complete capability."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _copy_contract_tree(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["capability_states"]["per_issue_cause_binding"] = (
                "implemented_on_protected_main"
            )
            manifest.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError,
                "protected-main operational proof",
            ):
                issue_detection_docs.audit_issue_detection_documentation(root, manifest)

    def test_inventory_counts_must_match_the_executable_registry(self) -> None:
        """The documentation graph cannot drift from the packaged detector registry."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _copy_contract_tree(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["inventory"]["claim_count"] = 416
            manifest.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError,
                "manifest claim_count does not match",
            ):
                issue_detection_docs.audit_issue_detection_documentation(root, manifest)

    def test_required_diagram_kind_cannot_be_replaced_by_prose(self) -> None:
        """A declared UML surface must retain executable diagram-as-code coverage."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _copy_contract_tree(root)
            uml_path = root / "docs" / "architecture" / "UML.md"
            uml_path.write_text("# UML\n\nNo diagrams.\n", encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError,
                "missing required Mermaid diagram",
            ):
                issue_detection_docs.audit_issue_detection_documentation(root, manifest)

    def test_malformed_manifest_reports_a_bounded_loading_error(self) -> None:
        """Invalid JSON fails at the manifest boundary without a parser traceback."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "docs" / "issue-detection-traceability.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text("{", encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError,
                "unable to load documentation manifest",
            ):
                issue_detection_docs.audit_issue_detection_documentation(root, manifest)

    def test_graph_alias_is_normalized_to_flowchart(self) -> None:
        """Mermaid's graph alias satisfies the architecture flowchart contract."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _copy_contract_tree(root)
            architecture = root / "ARCHITECTURE.md"
            architecture.write_text(
                architecture.read_text(encoding="utf-8").replace(
                    "flowchart TD",
                    "graph TD",
                    1,
                ),
                encoding="utf-8",
            )

            audit = issue_detection_docs.audit_issue_detection_documentation(
                root,
                manifest,
            )

            self.assertIn("flowchart", audit.diagram_kinds)
            self.assertNotIn("graph", audit.diagram_kinds)

    def test_invalid_utf8_artifact_reports_a_bounded_reading_error(self) -> None:
        """Non-UTF-8 canonical documentation fails closed at its exact path."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _copy_contract_tree(root)
            (root / "docs" / "product" / "PRD.md").write_bytes(b"\xff")

            with self.assertRaisesRegex(
                ValueError,
                "unable to read documentation artifact",
            ):
                issue_detection_docs.audit_issue_detection_documentation(root, manifest)


if __name__ == "__main__":
    unittest.main()
