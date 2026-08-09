"""Behavioral tests for the documentation topology/count/status guard."""

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
    for artifact in payload["supporting_artifacts"]:
        source = ROOT / artifact["path"]
        target = destination / artifact["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    for source in ROOT.rglob("*.md"):
        target = destination / source.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
    for source in ROOT.iterdir():
        if source.is_file():
            target = destination / source.name
            target.write_bytes(source.read_bytes())
    return target_manifest


class DocumentationContractTests(unittest.TestCase):
    """Prove declared documentation topology, counts, and states fail closed."""

    def test_repository_manifest_resolves_current_artifacts_and_diagrams(self) -> None:
        """A maintainer receives one validated, status-aware documentation graph."""
        audit = issue_detection_docs.audit_issue_detection_documentation(
            ROOT,
            MANIFEST_PATH,
        )

        self.assertEqual(audit.artifact_count, 11)
        self.assertEqual(audit.supporting_artifact_count, 10)
        self.assertEqual(audit.adr_count, 5)
        self.assertEqual(audit.documentation_delivery_state, "active_pr")
        self.assertGreater(audit.local_link_count, 0)
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
                "direct_detector_efficacy": "missing",
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

            with self.assertRaisesRegex(ValueError, "requires complete count"):
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

    def test_heading_and_root_or_self_anchor_links_are_validated(self) -> None:
        """Root-relative, same-file, duplicate-heading, and anchor paths are executable."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.md"
            target = root / "target.md"
            source.write_text(
                "# Local Heading\n\n[root](/target.md#section-one) "
                "[self](#local-heading)\n",
                encoding="utf-8",
            )
            target.write_text(
                "# Section *One*\n\n# Section One\n",
                encoding="utf-8",
            )

            self.assertEqual(
                issue_detection_docs._heading_anchors(target.read_text(encoding="utf-8")),
                {"section-one", "section-one-1"},
            )
            self.assertEqual(
                issue_detection_docs._validate_local_links(
                    root,
                    source,
                    source.read_text(encoding="utf-8"),
                ),
                2,
            )

    def test_invalid_iso_date_reports_bounded_metadata_error(self) -> None:
        """A superficially date-like but impossible assessment date fails closed."""
        payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        payload["assessment_date"] = "2026-02-31"

        with self.assertRaisesRegex(ValueError, "assessment_date must be an ISO date"):
            issue_detection_docs._validate_manifest_metadata(payload)

    def test_complete_count_requires_shipped_state(self) -> None:
        """A full self-declared count cannot remain partial or active-PR state."""
        with self.assertRaisesRegex(ValueError, "complete count requires shipped state"):
            issue_detection_docs._validate_completion_state(
                "test capability",
                "partial",
                3,
                3,
            )

    def test_direct_efficacy_shipped_state_requires_shipped_cause_binding(self) -> None:
        """Direct efficacy cannot be promoted above its per-issue cause identity."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _copy_contract_tree(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["capability_states"]["direct_detector_efficacy"] = (
                "implemented_on_protected_main"
            )
            payload["capability_states"]["per_issue_cause_binding"] = "partial"
            payload["inventory"]["direct_detector_efficacy_validated_claim_count"] = (
                payload["inventory"]["claim_count"]
            )
            manifest.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError,
                "requires shipped per-issue cause binding",
            ):
                issue_detection_docs.audit_issue_detection_documentation(root, manifest)

    def test_partial_direct_efficacy_requires_nonmissing_cause_binding(self) -> None:
        """Even one validated claim needs at least one explicit issue/cause boundary."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _copy_contract_tree(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["capability_states"]["direct_detector_efficacy"] = "partial"
            payload["inventory"]["direct_detector_efficacy_validated_claim_count"] = 1
            manifest.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError,
                "requires non-missing cause binding",
            ):
                issue_detection_docs.audit_issue_detection_documentation(root, manifest)

    def test_duplicate_artifact_path_fails_closed(self) -> None:
        """Two required roles cannot point at one token-bearing document."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _copy_contract_tree(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["artifacts"][1]["path"] = payload["artifacts"][0]["path"]
            manifest.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "duplicate declared artifact path"):
                issue_detection_docs.audit_issue_detection_documentation(root, manifest)

    def test_artifact_delivery_states_are_role_specific(self) -> None:
        """Current design docs cannot hide behind partial, and runbooks cannot overclaim current."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _copy_contract_tree(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["artifacts"][0]["state"] = "partial_in_active_pr"
            manifest.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "unexpected artifact delivery state"):
                issue_detection_docs.audit_issue_detection_documentation(root, manifest)

    def test_broken_local_link_fails_closed(self) -> None:
        """A canonical document cannot retain a missing repository-relative target."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _copy_contract_tree(root)
            architecture = root / "ARCHITECTURE.md"
            architecture.write_text(
                architecture.read_text(encoding="utf-8")
                + "\n[missing](docs/not-present.md)\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "broken local documentation link"):
                issue_detection_docs.audit_issue_detection_documentation(root, manifest)

    def test_orphan_adr_fails_closed(self) -> None:
        """Every status-bearing ADR detail must be discoverable from the index."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _copy_contract_tree(root)
            orphan = root / "docs" / "adr" / "ADR-9999-orphan.md"
            orphan.write_text(
                "# ADR-9999: Orphan\n\nStatus: Accepted\n\nDate: 2026-08-09\n\n"
                "Implementation: missing\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "incomplete or contains an orphan"):
                issue_detection_docs.audit_issue_detection_documentation(root, manifest)

    def test_supporting_artifact_set_is_exact(self) -> None:
        """Contributor, release, methodology, and workflow contracts cannot disappear."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _copy_contract_tree(root)
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["supporting_artifacts"].pop()
            manifest.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "supporting artifact set is incomplete"):
                issue_detection_docs.audit_issue_detection_documentation(root, manifest)

    def test_required_requirement_and_reference_tokens_cannot_disappear(self) -> None:
        """Stable PR/TR IDs and primary-reference identifiers remain machine-visible."""
        with TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = _copy_contract_tree(root)
            trd = root / "docs" / "engineering" / "TRD.md"
            trd.write_text(
                trd.read_text(encoding="utf-8").replace("TR-10", "TR-X", 1),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "missing TRD ID: TR-10"):
                issue_detection_docs.audit_issue_detection_documentation(root, manifest)


if __name__ == "__main__":
    unittest.main()
