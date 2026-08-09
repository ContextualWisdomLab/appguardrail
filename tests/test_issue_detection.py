"""Behavioral contracts for issue-derived AppGuardrail detection."""

from __future__ import annotations

import base64
from collections.abc import Mapping
import hashlib
import hmac
import importlib.util
import json
from io import StringIO
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).parents[1] / "appguardrail_core" / "issue_detection.py"
MODULE_SPEC = importlib.util.spec_from_file_location(
    "appguardrail_issue_detection_under_test",
    MODULE_PATH,
)
if MODULE_SPEC is None or MODULE_SPEC.loader is None:
    raise RuntimeError("unable to load issue detection module")
issue_detection = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = issue_detection
MODULE_SPEC.loader.exec_module(issue_detection)

WorkflowEvidence = issue_detection.WorkflowEvidence
audit_issue_coverage = issue_detection.audit_issue_coverage
audit_issue_requirements = issue_detection.audit_issue_requirements
compute_issue_requirement_sha256 = issue_detection.compute_issue_requirement_sha256
detect_workflow_causes = issue_detection.detect_workflow_causes
detector_family_for_job = issue_detection.detector_family_for_job
evaluate_detector_family = issue_detection.evaluate_detector_family
evaluate_issue_claim = issue_detection.evaluate_issue_claim
load_issue_detection_registry = issue_detection.load_issue_detection_registry
main = issue_detection.main
materialize_issue_claim_fixture = issue_detection.materialize_issue_claim_fixture
registered_detector_families = issue_detection.registered_detector_families


ATTESTATION_SECRET = b"appguardrail-test-attestation-key-v1"
SOURCE_REPOSITORY = "ContextualWisdomLab/appguardrail"
SOURCE_ARTIFACT_SHA256 = "b" * 64
WORKFLOW_SOURCE_IDENTITY = {
    "repository": SOURCE_REPOSITORY,
    "source_artifact_sha256": SOURCE_ARTIFACT_SHA256,
}


def workflow_result_verifier():
    """Build the trusted test verifier kept outside untrusted result JSON."""
    return issue_detection.WorkflowResultVerifier(ATTESTATION_SECRET)


def resign_workflow_result_envelope(envelope: dict[str, object]) -> None:
    """Recompute the digest and HMAC after a test mutates an envelope."""
    payload = envelope["payload"]
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    envelope["payload_sha256"] = hashlib.sha256(canonical).hexdigest()
    attested_fields = {
        key: envelope[key]
        for key in (
            "schema",
            "producer",
            "repository",
            "run_id",
            "head_sha",
            "evidence_ref",
            "source_artifact_sha256",
            "payload_sha256",
        )
    }
    attested = json.dumps(
        attested_fields,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    envelope["attestation"] = hmac.new(
        ATTESTATION_SECRET,
        attested,
        hashlib.sha256,
    ).hexdigest()


def workflow_result_envelope(
    outcome: str,
    *,
    producer: str = "strix",
    run_id: str = "run-1",
    head_sha: str = "a" * 40,
    detector_id: str = "strix.finding",
    rule_id: str = "finding",
    cause_class: str = "provider_rate_limit",
) -> dict[str, object]:
    """Build a canonical digest-bound workflow result test envelope."""
    payload: dict[str, object] = {
        "schema": "appguardrail.workflow-result.v1",
        "outcome": outcome,
    }
    if outcome == "finding":
        payload["detector_id"] = detector_id
        payload["rule_id"] = rule_id
    elif outcome == "operational_failure":
        payload["cause_class"] = cause_class
    envelope = {
        "schema": "appguardrail.workflow-result-envelope.v2",
        "producer": producer,
        "repository": SOURCE_REPOSITORY,
        "run_id": run_id,
        "head_sha": head_sha,
        "evidence_ref": f"artifact://{producer}/result.json",
        "source_artifact_sha256": SOURCE_ARTIFACT_SHA256,
        "payload": payload,
        "payload_sha256": "",
    }
    resign_workflow_result_envelope(envelope)
    return envelope


class WorkflowCauseDetectionTests(unittest.TestCase):
    """Prove representative historical issues resolve to their real cause classes."""

    def test_issue_815_preserves_candidate_and_publication_failure(self) -> None:
        """Free-form review output remains unconfirmed and fail-closed."""
        evidence = WorkflowEvidence(
            workflow_name="OpenCode Review Dispatch",
            job_name="opencode-review",
            conclusion="failure",
            log_text=(
                "REQUEST_CHANGES: secret-redaction failure-path regression confirmed\n"
                "gh: Resource not accessible by integration (HTTP 403)\n"
            ),
        )

        results = detect_workflow_causes(evidence)

        self.assertEqual(
            [(item.detector_id, item.status) for item in results],
            [
                ("opencode.change_request_observed", "inconclusive"),
                ("github.publication_permission_denied", "reporting_failed"),
            ],
        )
        self.assertIsNone(results[0].confirmed_security_finding)
        self.assertFalse(results[0].gate_satisfied)
        self.assertFalse(results[1].deploy_blocking)
        self.assertFalse(results[1].gate_satisfied)

    def test_issue_813_detects_rate_limit_without_inventing_vulnerability(self) -> None:
        """A zero-finding NVIDIA 429 cancellation is a dependency failure."""
        evidence = WorkflowEvidence(
            workflow_name="Strix Security Scan",
            job_name="strix",
            conclusion="cancelled",
            log_text=(
                "litellm.RateLimitError: Nvidia_nimException - Error code: 429\n"
                "Vulnerabilities 0\n"
                "The operation was canceled.\n"
            ),
        )

        results = detect_workflow_causes(evidence)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].detector_id, "provider.rate_limit")
        self.assertEqual(results[0].status, "dependency_failure")
        self.assertEqual(results[0].confirmed_security_finding, False)
        self.assertFalse(results[0].deploy_blocking)
        self.assertFalse(results[0].gate_satisfied)

    def test_issue_763_log_only_control_observation_is_inconclusive(self) -> None:
        """A free-form dispatch rejection cannot prove the control result."""
        evidence = WorkflowEvidence(
            workflow_name="OpenCode Review Dispatch",
            job_name="validate-pr-metadata",
            conclusion="failure",
            log_text=(
                "::error::repository_dispatch authorization rejected actor=untrusted "
                "sender=untrusted because both must match the scheduler identity.\n"
            ),
        )

        results = detect_workflow_causes(evidence)

        self.assertEqual(len(results), 1)
        self.assertEqual(
            results[0].detector_id,
            "control.repository_dispatch_rejection_observed",
        )
        self.assertEqual(results[0].status, "inconclusive")
        self.assertFalse(results[0].deploy_blocking)
        self.assertFalse(results[0].gate_satisfied)

    def test_metadata_only_cancellation_remains_detected_and_inconclusive(self) -> None:
        """A missing authorized log still yields an explicit detection outcome."""
        results = detect_workflow_causes(
            WorkflowEvidence(
                workflow_name="Required OpenCode Review",
                job_name="opencode-review",
                conclusion="cancelled",
                log_text="",
            )
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].detector_id, "workflow.cancelled_unclassified")
        self.assertEqual(results[0].status, "inconclusive")
        self.assertEqual(results[0].confidence, "metadata_only")
        self.assertFalse(results[0].gate_satisfied)

    def test_free_form_scanner_count_is_not_a_confirmed_finding(self) -> None:
        """A log count without bound structured provenance stays inconclusive."""
        results = detect_workflow_causes(
            WorkflowEvidence(
                workflow_name="Strix Security Scan",
                job_name="strix",
                conclusion="failure",
                log_text="Vulnerabilities 2\n",
            )
        )

        self.assertEqual(results[0].detector_id, "scanner.vulnerability_count_observed")
        self.assertIsNone(results[0].confirmed_security_finding)
        self.assertEqual(results[0].status, "inconclusive")
        self.assertFalse(results[0].gate_satisfied)

    def test_bound_structured_result_is_a_confirmed_finding(self) -> None:
        """Confirm only a schema-valid result bound to the expected run and head."""
        evidence = WorkflowEvidence(
            workflow_name="Strix Security Scan",
            job_name="strix",
            conclusion="failure",
            run_id="91554698847",
            head_sha="a" * 40,
            structured_result=workflow_result_envelope(
                "finding",
                run_id="91554698847",
                detector_id="strix.secret-redaction-regression",
                rule_id="secret-redaction-regression",
            ),
        )

        results = detect_workflow_causes(
            evidence,
            workflow_result_verifier=workflow_result_verifier(),
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(
            results[0].detector_id,
            "strix.secret-redaction-regression",
        )
        self.assertTrue(results[0].confirmed_security_finding)
        self.assertTrue(results[0].deploy_blocking)
        self.assertFalse(results[0].gate_satisfied)
        self.assertEqual(results[0].confidence, "structured_result")

    def test_authenticated_operational_failure_retains_exact_cause(self) -> None:
        """A producer-authenticated cause is executable without trusting log prose."""
        evidence = WorkflowEvidence(
            workflow_name="Strix Security Scan",
            job_name="strix",
            conclusion="failure",
            run_id="run-1",
            head_sha="a" * 40,
            structured_result=workflow_result_envelope(
                "operational_failure",
                cause_class="scanner_setup",
            ),
        )

        result = detect_workflow_causes(
            evidence,
            workflow_result_verifier=workflow_result_verifier(),
        )[0]

        self.assertEqual(result.status, "dependency_failure")
        self.assertEqual(result.cause_class, "scanner_setup")
        self.assertFalse(result.gate_satisfied)

        unregistered_cause = workflow_result_envelope(
            "operational_failure",
            cause_class="future_unreviewed_cause",
        )
        rejected = detect_workflow_causes(
            WorkflowEvidence(
                workflow_name="Strix Security Scan",
                job_name="strix",
                conclusion="failure",
                run_id="run-1",
                head_sha="a" * 40,
                structured_result=unregistered_cause,
            ),
            workflow_result_verifier=workflow_result_verifier(),
        )[0]
        self.assertEqual(
            rejected.detector_id,
            "workflow.structured_result_invalid",
        )
        self.assertFalse(rejected.gate_satisfied)

    def test_structured_result_payload_and_envelope_are_closed(self) -> None:
        """Authenticated but unsupported fields cannot acquire clean authority."""
        extra_payload = workflow_result_envelope("clean")
        extra_payload["payload"]["future_claim"] = True
        resign_workflow_result_envelope(extra_payload)
        extra_envelope = workflow_result_envelope("clean")
        extra_envelope["future_claim"] = True
        resign_workflow_result_envelope(extra_envelope)

        for structured_result in (extra_payload, extra_envelope):
            with self.subTest(structured_result=structured_result):
                result = detect_workflow_causes(
                    WorkflowEvidence(
                        workflow_name="Strix Security Scan",
                        job_name="strix",
                        conclusion="success",
                        run_id="run-1",
                        head_sha="a" * 40,
                        structured_result=structured_result,
                    ),
                    workflow_result_verifier=workflow_result_verifier(),
                )[0]
                self.assertEqual(
                    result.detector_id,
                    "workflow.structured_result_invalid",
                )
                self.assertFalse(result.gate_satisfied)

    def test_workflow_result_verifier_rejects_weak_or_malformed_capabilities(
        self,
    ) -> None:
        """Only a valid external key and complete attested metadata can verify."""
        verifier = workflow_result_verifier()
        encoded_key = base64.b64encode(ATTESTATION_SECRET).decode("ascii")

        self.assertEqual(repr(verifier), "WorkflowResultVerifier(key=<redacted>)")
        self.assertEqual(
            issue_detection.WorkflowResultVerifier.from_base64(encoded_key),
            verifier,
        )
        with self.assertRaisesRegex(ValueError, "32 bytes"):
            issue_detection.WorkflowResultVerifier(b"weak")
        with self.assertRaisesRegex(ValueError, "invalid base64"):
            issue_detection.WorkflowResultVerifier.from_base64("not base64!")
        self.assertFalse(verifier.verify({}))
        self.assertFalse(verifier.verify({"attestation": "0" * 64}))

    def test_attestation_binds_repository_and_source_artifact_identity(self) -> None:
        """Repository or source-artifact substitution invalidates the envelope."""
        verifier = workflow_result_verifier()
        valid = workflow_result_envelope("clean")

        self.assertTrue(verifier.verify(valid))
        for field, replacement in (
            ("repository", "ContextualWisdomLab/another-repository"),
            ("source_artifact_sha256", "c" * 64),
        ):
            forged = json.loads(json.dumps(valid))
            forged[field] = replacement
            with self.subTest(field=field):
                self.assertFalse(verifier.verify(forged))

    def test_unbound_structured_result_fails_closed(self) -> None:
        """A mismatched run/head result cannot satisfy or confirm a security gate."""
        evidence = WorkflowEvidence(
            workflow_name="Strix Security Scan",
            job_name="strix",
            conclusion="failure",
            run_id="expected-run",
            head_sha="a" * 40,
            structured_result=workflow_result_envelope(
                "finding",
                run_id="different-run",
            ),
        )

        results = detect_workflow_causes(
            evidence,
            workflow_result_verifier=workflow_result_verifier(),
        )

        self.assertEqual(results[0].detector_id, "workflow.structured_result_invalid")
        self.assertIsNone(results[0].confirmed_security_finding)
        self.assertFalse(results[0].gate_satisfied)

    def test_structured_result_from_unregistered_job_fails_closed(self) -> None:
        """A future producer cannot borrow a detector family by result shape alone."""
        results = detect_workflow_causes(
            WorkflowEvidence(
                workflow_name="Future Security Engine",
                job_name="future-security-engine",
                conclusion="failure",
                run_id="run-1",
                head_sha="a" * 40,
                structured_result=workflow_result_envelope(
                    "finding",
                    producer="future-security-engine",
                    detector_id="future.finding",
                ),
            ),
            workflow_result_verifier=workflow_result_verifier(),
        )

        self.assertEqual(
            results[0].detector_id,
            "workflow.structured_result_invalid",
        )
        self.assertEqual(results[0].detector_family, "unregistered")

    def test_self_asserted_clean_envelope_cannot_satisfy_successful_gate(self) -> None:
        """Digest and producer claims are insufficient without trusted verification."""
        results = detect_workflow_causes(
            WorkflowEvidence(
                workflow_name="Strix Security Scan",
                job_name="strix",
                conclusion="success",
                run_id="run-1",
                head_sha="a" * 40,
                structured_result=workflow_result_envelope("clean"),
            )
        )

        self.assertEqual(
            results[0].detector_id,
            "workflow.structured_result_invalid",
        )
        self.assertFalse(results[0].gate_satisfied)

    def test_log_control_observation_cannot_suppress_attested_finding(self) -> None:
        """Untrusted log text cannot short-circuit an authenticated finding."""
        results = detect_workflow_causes(
            WorkflowEvidence(
                workflow_name="Strix Security Scan",
                job_name="strix",
                conclusion="failure",
                log_text="repository_dispatch authorization rejected",
                run_id="run-1",
                head_sha="a" * 40,
                structured_result=workflow_result_envelope("finding"),
            ),
            workflow_result_verifier=workflow_result_verifier(),
        )

        self.assertTrue(
            any(result.confirmed_security_finding is True for result in results)
        )
        self.assertTrue(any(result.deploy_blocking for result in results))

    def test_structured_nonfinding_outcomes_have_explicit_gate_semantics(self) -> None:
        """Clean, policy-blocked, and operational outcomes stay distinguishable."""
        expected = {
            "clean": ("clean", False, False),
            "control_blocked": ("control_blocked", False, False),
            "operational_failure": ("dependency_failure", False, None),
        }

        for outcome, contract in expected.items():
            with self.subTest(outcome=outcome):
                results = detect_workflow_causes(
                    WorkflowEvidence(
                        workflow_name="Strix Security Scan",
                        job_name="strix",
                        conclusion="failure",
                        run_id="run-1",
                        head_sha="a" * 40,
                        structured_result=workflow_result_envelope(outcome),
                    ),
                    workflow_result_verifier=workflow_result_verifier(),
                )

                status, gate_satisfied, confirmed = contract
                self.assertEqual(results[0].status, status)
                self.assertEqual(results[0].gate_satisfied, gate_satisfied)
                self.assertEqual(results[0].confirmed_security_finding, confirmed)

    def test_malformed_structured_results_are_rejected_at_each_boundary(self) -> None:
        """Schema, identity, provenance, and digest failures all fail closed."""
        base = workflow_result_envelope("finding")
        cases = []
        cases.append(([], "run-1", "a" * 40))
        for key, value in (
            ("schema", None),
            ("schema", "wrong-schema"),
            ("head_sha", "c" * 40),
            ("payload_sha256", "not-a-digest"),
            ("producer", "unrelated-producer"),
            ("producer", "s"),
            ("repository", "not-a-repository"),
            ("source_artifact_sha256", "not-a-digest"),
        ):
            result = json.loads(json.dumps(base))
            if value is None:
                result.pop(key)
            else:
                result[key] = value
            cases.append((result, "run-1", "a" * 40))
        wrong_payload_schema = json.loads(json.dumps(base))
        wrong_payload_schema["payload"]["schema"] = "wrong-schema"
        cases.append((wrong_payload_schema, "run-1", "a" * 40))
        wrong_outcome = json.loads(json.dumps(base))
        wrong_outcome["payload"]["outcome"] = "unsupported"
        cases.append((wrong_outcome, "run-1", "a" * 40))
        for unhashable_outcome in ([], {}):
            wrong_outcome_type = json.loads(json.dumps(base))
            wrong_outcome_type["payload"]["outcome"] = unhashable_outcome
            cases.append((wrong_outcome_type, "run-1", "a" * 40))
        missing_payload = json.loads(json.dumps(base))
        missing_payload.pop("payload")
        cases.append((missing_payload, "run-1", "a" * 40))
        invalid_identifier = workflow_result_envelope(
            "finding",
            detector_id="invalid identifier",
        )
        cases.append((invalid_identifier, "run-1", "a" * 40))
        forged_digest = json.loads(json.dumps(base))
        forged_digest["payload"]["rule_id"] = "forged"
        cases.append((forged_digest, "run-1", "a" * 40))
        forged_attestation = json.loads(json.dumps(base))
        forged_attestation["attestation"] = "0" * 64
        cases.append((forged_attestation, "run-1", "a" * 40))
        cases.append((json.loads(json.dumps(base)), "run-1", "not-a-sha"))

        for index, (result, run_id, head_sha) in enumerate(cases):
            with self.subTest(case=index):
                detections = detect_workflow_causes(
                    WorkflowEvidence(
                        workflow_name="Strix Security Scan",
                        job_name="strix",
                        conclusion="failure",
                        run_id=run_id,
                        head_sha=head_sha,
                        structured_result=result,
                    ),
                    workflow_result_verifier=workflow_result_verifier(),
                )
                self.assertEqual(
                    detections[0].detector_id,
                    "workflow.structured_result_invalid",
                )

    def test_non_mapping_structured_result_fails_closed_without_crashing(self) -> None:
        """Malformed structured evidence is hashable and explicitly rejected."""
        for result in ("forged", ["forged"]):
            with self.subTest(result=result):
                detections = detect_workflow_causes(
                    WorkflowEvidence(
                        workflow_name="Strix Security Scan",
                        job_name="strix",
                        conclusion="success",
                        run_id="run-1",
                        head_sha="a" * 40,
                        structured_result=result,
                    ),
                    workflow_result_verifier=workflow_result_verifier(),
                )
                self.assertEqual(
                    detections[0].detector_id,
                    "workflow.structured_result_invalid",
                )
                self.assertFalse(detections[0].gate_satisfied)

    def test_non_unicode_scalar_result_text_fails_closed_without_crashing(self) -> None:
        """JSON lone surrogates cannot crash payload or attestation canonicalization."""
        payload_surrogate = workflow_result_envelope("finding")
        payload_surrogate["payload"]["extra"] = "\ud800"
        reference_surrogate = workflow_result_envelope("finding")
        reference_surrogate["evidence_ref"] = "\ud800"

        for result in (payload_surrogate, reference_surrogate):
            with self.subTest(field=result):
                detections = detect_workflow_causes(
                    WorkflowEvidence(
                        workflow_name="Strix Security Scan",
                        job_name="strix",
                        conclusion="failure",
                        run_id="run-1",
                        head_sha="a" * 40,
                        structured_result=result,
                    ),
                    workflow_result_verifier=workflow_result_verifier(),
                )
                self.assertEqual(
                    detections[0].detector_id,
                    "workflow.structured_result_invalid",
                )
                self.assertFalse(detections[0].gate_satisfied)

    def test_coverage_rejection_is_a_quality_control_event(self) -> None:
        """Missing coverage evidence must not masquerade as a security finding."""
        results = detect_workflow_causes(
            WorkflowEvidence(
                workflow_name="Coverage Evidence",
                job_name="coverage-evidence",
                conclusion="failure",
                log_text="Coverage artifact missing; threshold check failed.\n",
            )
        )

        self.assertEqual(results[0].detector_id, "control.coverage_evidence_rejected")
        self.assertEqual(results[0].status, "control_blocked")
        self.assertEqual(results[0].confirmed_security_finding, False)
        self.assertFalse(results[0].gate_satisfied)

    def test_timeout_and_unclassified_failure_remain_explicit(self) -> None:
        """Operational failures produce a typed result without a known root cause."""
        timeout = detect_workflow_causes(
            WorkflowEvidence(
                workflow_name="CodeQL",
                job_name="CodeQL analysis",
                conclusion="timed_out",
            )
        )
        unknown = detect_workflow_causes(
            WorkflowEvidence(
                workflow_name="Security Process",
                job_name="custom-security-job",
                conclusion="failure",
            )
        )

        self.assertEqual(timeout[0].detector_id, "workflow.execution_timeout")
        self.assertEqual(
            timeout[0].detector_family, "codeql-analysis-gate-diagnostics"
        )
        self.assertEqual(unknown[0].detector_id, "workflow.failure_unclassified")
        self.assertEqual(
            unknown[0].detector_family, "unregistered"
        )
        self.assertFalse(timeout[0].gate_satisfied)
        self.assertFalse(unknown[0].gate_satisfied)

    def test_structured_result_never_serializes_raw_log_or_secret(self) -> None:
        """Classification may inspect logs but emits only bounded evidence."""
        evidence = WorkflowEvidence(
            workflow_name="OpenCode Review Dispatch",
            job_name="opencode-review",
            conclusion="failure",
            log_text=(
                "REQUEST_CHANGES: regression confirmed password=do-not-publish\n"
                "gh: Resource not accessible by integration (HTTP 403)\n"
            ),
        )

        first = [item.as_dict() for item in detect_workflow_causes(evidence)]
        second = [item.as_dict() for item in detect_workflow_causes(evidence)]
        serialized = json.dumps(first, sort_keys=True)

        self.assertEqual(first, second)
        self.assertNotIn("do-not-publish", serialized)
        self.assertNotIn("raw_log", serialized)
        self.assertTrue(all(len(item["evidence_hash"]) == 64 for item in first))


class DetectionRegistryTests(unittest.TestCase):
    """Keep every repository issue bound to a concrete detector family."""

    def test_every_historical_issue_is_retained_in_registry(self) -> None:
        """The live 2026-08-09 inventory contains exactly 414 retained requirements."""
        registry = load_issue_detection_registry()
        numbers = tuple(target.issue_number for target in registry.issues)
        inventory_path = (
            Path(__file__).parent
            / "fixtures"
            / "appguardrail_issue_numbers_2026-08-09.json"
        )
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))

        self.assertEqual(registry.schema, "appguardrail.issue-detection-registry.v1")
        self.assertEqual(inventory["schema"], "appguardrail.github-issue-inventory.v1")
        self.assertEqual(numbers, tuple(inventory["issue_numbers"]))
        self.assertEqual(
            {
                target.issue_number: target.requirement_sha256
                for target in registry.issues
            },
            {
                record["issue_number"]: record["requirement_sha256"]
                for record in inventory["issue_records"]
            },
        )
        self.assertEqual(registry.issue_count, 414)
        self.assertEqual(len(numbers), 414)
        self.assertEqual(len(set(numbers)), 414)
        self.assertEqual((numbers[0], numbers[-1]), (132, 894))
        self.assertIn(536, numbers)
        self.assertTrue(
            all(target.retained_detection_requirement for target in registry.issues)
        )
        self.assertTrue(all(target.claims for target in registry.issues))

    def test_issue_132_retains_each_independent_claim(self) -> None:
        """The preliminary audit's distinct obligations may not be collapsed."""
        registry = load_issue_detection_registry()
        issue = next(target for target in registry.issues if target.issue_number == 132)

        self.assertEqual(
            {claim.claim_id for claim in issue.claims},
            {
                "defensive-path-and-process-controls",
                "privileged-review-workflow",
                "release-integrity",
                "secret-output-redaction",
            },
        )
        self.assertTrue(
            all(
                target.detector_family in registry.detector_families
                for target in registry.issues
            )
        )

    def test_registry_covers_all_seventeen_detector_families(self) -> None:
        """Product, governance, scanner, and workflow targets all remain addressable."""
        registry = load_issue_detection_registry()

        self.assertEqual(len(registry.detector_families), 17)
        self.assertEqual(
            set(registry.detector_families),
            set(registered_detector_families()),
        )
        required_contract_fields = {
            "cluster_id",
            "condition",
            "evidence_sources",
            "expected_structured_outcome",
        }
        self.assertTrue(
            all(
                required_contract_fields <= set(contract)
                for contract in registry.detector_families.values()
            )
        )
        self.assertEqual(
            detector_family_for_job("opencode-review"),
            "opencode-review-gate-diagnostics",
        )
        expected = {
            "strix": "strix-security-gate-diagnostics",
            "publish-manual-pr-evidence-status": "pr-evidence-publication-health",
            "coverage-evidence": "coverage-evidence-control",
            "trivy-fs": "trivy-filesystem-gate-diagnostics",
            "validate-pr-metadata": "pull-request-metadata-policy",
            "noema-review": "noema-review-gate-diagnostics",
            "CodeQL analysis": "codeql-analysis-gate-diagnostics",
            "CodeQL merge preview (python)": "codeql-analysis-gate-diagnostics",
            "appguardrail-scan": "native-appguardrail-gate-diagnostics",
        }
        self.assertEqual(
            {job: detector_family_for_job(job) for job in expected},
            expected,
        )

    def test_every_family_executes_positive_negative_unknown_contract(self) -> None:
        """A declared family is incomplete until all three evidence states execute."""
        registry = load_issue_detection_registry()

        for family, contract in registry.detector_families.items():
            for fixture_name, expected_status in (
                ("positive", "detected"),
                ("negative", "clean"),
                ("unknown", "unknown"),
            ):
                with self.subTest(family=family, fixture=fixture_name):
                    evidence = contract["fixtures"][fixture_name]
                    self.assertNotIn('"state"', json.dumps(evidence, sort_keys=True))
                    assessment = evaluate_detector_family(
                        family,
                        evidence,
                        registry=registry,
                        workflow_result_verifier=workflow_result_verifier(),
                    )
                    self.assertEqual(assessment.status, expected_status)

    def test_every_declared_obligation_executes_three_way_raw_evidence(self) -> None:
        """Each condition branch has its own detected, clean, and unknown proof."""
        registry = load_issue_detection_registry()

        for family, contract in registry.detector_families.items():
            obligations = contract["obligations"]
            self.assertTrue(obligations)
            self.assertEqual(
                len(obligations),
                len({item["obligation_id"] for item in obligations}),
            )
            for obligation in obligations:
                fixtures = obligation["fixtures"]
                positive = json.loads(
                    json.dumps(contract["fixtures"]["negative"])
                )
                positive.update(fixtures["positive_patch"])
                negative = json.loads(
                    json.dumps(contract["fixtures"]["negative"])
                )
                negative.update(fixtures["negative_patch"])
                unknown = json.loads(
                    json.dumps(contract["fixtures"]["negative"])
                )
                for field in fixtures["unknown_remove_fields"]:
                    unknown.pop(field, None)

                for label, evidence, expected in (
                    (
                        "positive",
                        positive,
                        obligation.get("positive_status", "detected"),
                    ),
                    ("negative", negative, "clean"),
                    ("unknown", unknown, "unknown"),
                ):
                    with self.subTest(
                        family=family,
                        obligation=obligation["obligation_id"],
                        fixture=label,
                    ):
                        assessment = evaluate_detector_family(
                            family,
                            evidence,
                            registry=registry,
                            workflow_result_verifier=workflow_result_verifier(),
                        )
                        self.assertEqual(assessment.status, expected)

    def test_unsupported_violation_fields_never_produce_clean(self) -> None:
        """A complete evidence object is closed; ignored violations are unknown."""
        registry = load_issue_detection_registry()
        injections = {
            "tenant-retention-and-audit-posture": {
                "future_tenant_violation": True,
            },
            "scheduled-agent-workflow-governance": {
                "future_governance_violation": True,
            },
            "authenticated-egress-destination-and-redirect-safety": {
                "future_egress_violation": True,
            },
        }

        for family, injected in injections.items():
            evidence = json.loads(
                json.dumps(registry.detector_families[family]["fixtures"]["negative"])
            )
            evidence.update(injected)
            with self.subTest(family=family):
                assessment = evaluate_detector_family(
                    family,
                    evidence,
                    registry=registry,
                )
                self.assertEqual(assessment.status, "unknown")
                self.assertFalse(assessment.gate_satisfied)

    def test_malformed_evidence_is_unknown_instead_of_crashing_or_passing(self) -> None:
        """Invalid scalar types never become a clean or inferred finding result."""
        registry = load_issue_detection_registry()
        invalid_fields = {
            "authenticated-egress-destination-and-redirect-safety": (
                "resolved_ip_public",
                "true",
            ),
            "scheduled-agent-workflow-governance": ("timeout_minutes", "invalid"),
            "scanner-path-contract-and-performance": ("elapsed_ms", "invalid"),
            "scheduled-builder-runtime-contract": ("timeout_minutes", "invalid"),
            "tenant-retention-and-audit-posture": ("policy_days", True),
            "pr-evidence-publication-health": ("status_code", True),
            "coverage-evidence-control": ("measured_percent", True),
        }

        for family, (field, value) in invalid_fields.items():
            with self.subTest(family=family, field=field):
                evidence = json.loads(
                    json.dumps(
                        registry.detector_families[family]["fixtures"]["negative"]
                    )
                )
                evidence[field] = value
                assessment = evaluate_detector_family(
                    family,
                    evidence,
                    registry=registry,
                )
                self.assertEqual(assessment.status, "unknown")
                self.assertFalse(assessment.gate_satisfied)

        path_evidence = json.loads(
            json.dumps(
                registry.detector_families[
                    "scanner-path-contract-and-performance"
                ]["fixtures"]["negative"]
            )
        )
        path_evidence["scan_root"] = "\x00"
        path_result = evaluate_detector_family(
            "scanner-path-contract-and-performance",
            path_evidence,
            registry=registry,
        )
        self.assertEqual(path_result.status, "unknown")

        coverage_evidence = json.loads(
            json.dumps(
                registry.detector_families["coverage-evidence-control"][
                    "fixtures"
                ]["negative"]
            )
        )
        coverage_evidence["measured_percent"] = 10**10000
        coverage_result = evaluate_detector_family(
            "coverage-evidence-control",
            coverage_evidence,
            registry=registry,
        )
        self.assertEqual(coverage_result.status, "unknown")

        workflow_family = "strix-security-gate-diagnostics"
        workflow_evidence = json.loads(
            json.dumps(
                registry.detector_families[workflow_family]["fixtures"]["negative"]
            )
        )
        workflow_evidence["run_id"] = 10**5000
        workflow_result = evaluate_detector_family(
            workflow_family,
            workflow_evidence,
            registry=registry,
            workflow_result_verifier=workflow_result_verifier(),
        )
        self.assertEqual(workflow_result.status, "unknown")

        direct_result = detect_workflow_causes(
            WorkflowEvidence(
                workflow_name="Strix Security Scan",
                job_name="strix",
                conclusion="failure",
                run_id=10**5000,
                head_sha=10**5000,
                structured_result=workflow_result_envelope("finding"),
            ),
            workflow_result_verifier=workflow_result_verifier(),
        )
        self.assertEqual(
            direct_result[0].detector_id,
            "workflow.structured_result_invalid",
        )
        self.assertEqual(detector_family_for_job(10**5000), "unregistered")

        assessment = evaluate_detector_family(
            "product-security-audit-controls",
            [],
            registry=registry,
        )
        self.assertEqual(assessment.status, "unknown")
        self.assertFalse(assessment.gate_satisfied)

    def test_adapter_edge_evidence_is_typed_and_fail_closed(self) -> None:
        """Missing or malformed secondary fields cannot bypass an adapter."""
        registry = load_issue_detection_registry()

        cases = []
        product = {
            "schema": "appguardrail.detector-evidence.product-security-audit.v1",
            "findings": [1],
            "verified_controls": [],
        }
        cases.append(("product-security-audit-controls", product, "unknown"))
        cases.append(
            (
                "openssf-best-practices-evidence",
                {"schema": "wrong-schema"},
                "unknown",
            )
        )
        for family, field in (
            ("scheduled-agent-workflow-governance", "provider_key_name"),
            (
                "authenticated-egress-destination-and-redirect-safety",
                "scheme",
            ),
            ("scanner-path-contract-and-performance", "scan_root"),
            ("scheduled-builder-runtime-contract", "timeout_minutes"),
        ):
            evidence = json.loads(
                json.dumps(registry.detector_families[family]["fixtures"]["negative"])
            )
            evidence.pop(field)
            cases.append((family, evidence, "unknown"))

        workflow_family = "strix-security-gate-diagnostics"
        workflow_schema = registry.detector_families[workflow_family]["evidence_schema"]
        rate_limited = json.loads(
            json.dumps(
                registry.detector_families[workflow_family]["fixtures"]["negative"]
            )
        )
        rate_limited.update(
            conclusion="failure",
            log_text="HTTP 429 too many requests",
            structured_result=None,
        )
        cases.extend(
            (
                (workflow_family, {"schema": "wrong-schema"}, "unknown"),
                (
                    workflow_family,
                    {"schema": workflow_schema, "workflow_name": "Strix"},
                    "unknown",
                ),
                (
                    workflow_family,
                    {
                        "schema": workflow_schema,
                        "workflow_name": "Future",
                        "job_name": "future-security-engine",
                        "conclusion": "failure",
                    },
                    "unknown",
                ),
                (
                    workflow_family,
                    rate_limited,
                    "detected",
                ),
            )
        )

        coverage = json.loads(
            json.dumps(
                registry.detector_families["coverage-evidence-control"][
                    "fixtures"
                ]["negative"]
            )
        )
        coverage["artifact_valid"] = "true"
        cases.append(("coverage-evidence-control", coverage, "unknown"))
        metadata = json.loads(
            json.dumps(
                registry.detector_families["pull-request-metadata-policy"][
                    "fixtures"
                ]["negative"]
            )
        )
        metadata["actor_matches_scheduler"] = "true"
        cases.append(("pull-request-metadata-policy", metadata, "unknown"))

        for family, evidence, expected in cases:
            with self.subTest(family=family, expected=expected):
                assessment = evaluate_detector_family(
                    family,
                    evidence,
                    registry=registry,
                    workflow_result_verifier=workflow_result_verifier(),
                )
                self.assertEqual(assessment.status, expected)
                self.assertFalse(assessment.gate_satisfied)

    def test_defensive_adapter_and_shape_branches_fail_closed(self) -> None:
        """Private adapter boundaries remain total even outside public dispatch."""
        registry = load_issue_detection_registry()

        class ExplodingKeys(dict):
            def keys(self):
                raise RuntimeError("untrusted mapping")

        self.assertEqual(
            issue_detection._evidence_shape_error({}, {}),
            "invalid_evidence_contract",
        )
        product_contract = registry.detector_families[
            "product-security-audit-controls"
        ]
        self.assertEqual(
            issue_detection._evidence_shape_error({1: True}, product_contract),
            "invalid_evidence_field",
        )
        self.assertEqual(
            issue_detection._evidence_shape_error(
                ExplodingKeys(),
                product_contract,
            ),
            "invalid_evidence_field",
        )
        self.assertFalse(
            issue_detection._valid_obligation_contract([], {"schema"}, {"schema"})
        )

        def raw_fixture(family):
            return json.loads(
                json.dumps(
                    registry.detector_families[family]["fixtures"]["negative"]
                )
            )

        def direct(family, evidence, claim_id=None):
            adapter = issue_detection._FAMILY_ADAPTERS[family]
            contract = registry.detector_families[family]
            if adapter is issue_detection._workflow_adapter:
                return adapter(
                    family,
                    evidence,
                    contract,
                    claim_id,
                    workflow_result_verifier(),
                )
            return adapter(family, evidence, contract, claim_id)

        for family in registered_detector_families():
            wrong_schema = raw_fixture(family)
            wrong_schema["schema"] = "unreviewed.schema"
            with self.subTest(family=family, branch="wrong-schema"):
                self.assertEqual(direct(family, wrong_schema).status, "unknown")

        product = raw_fixture("product-security-audit-controls")
        self.assertEqual(
            direct(
                "product-security-audit-controls",
                product,
                "unregistered-product-claim",
            ).status,
            "unknown",
        )
        code_scanning = raw_fixture("github-code-scanning-analysis-drift")
        code_scanning["base_analysis_keys"] = [1]
        self.assertEqual(
            direct("github-code-scanning-analysis-drift", code_scanning).status,
            "unknown",
        )
        egress = raw_fixture(
            "authenticated-egress-destination-and-redirect-safety"
        )
        egress["scheme"] = 1
        self.assertEqual(
            direct(
                "authenticated-egress-destination-and-redirect-safety",
                egress,
            ).status,
            "unknown",
        )

        for family, field in (
            ("scheduled-agent-workflow-governance", "provider_key_name"),
            (
                "authenticated-egress-destination-and-redirect-safety",
                "scheme",
            ),
            ("scanner-path-contract-and-performance", "scan_root"),
            ("scheduled-builder-runtime-contract", "timeout_minutes"),
            ("strix-security-gate-diagnostics", "job_name"),
        ):
            missing = raw_fixture(family)
            missing.pop(field)
            with self.subTest(family=family, branch="missing-field"):
                self.assertEqual(direct(family, missing).status, "unknown")

        mismatch = raw_fixture("strix-security-gate-diagnostics")
        mismatch["job_name"] = "opencode-review"
        self.assertEqual(
            direct("strix-security-gate-diagnostics", mismatch).status,
            "unknown",
        )

    def test_structured_result_defensive_shapes_fail_closed(self) -> None:
        """Every early structured-result rejection is exception-free and bounded."""
        verifier = workflow_result_verifier()
        valid = workflow_result_envelope("clean")
        evidence = WorkflowEvidence(
            workflow_name="Strix Security Scan",
            job_name="strix",
            conclusion="success",
            run_id="run-1",
            head_sha="a" * 40,
            structured_result=valid,
        )
        self.assertFalse(issue_detection._structured_result_is_bound(evidence, None))

        missing_text = workflow_result_envelope("clean")
        missing_text["attestation"] = ""
        self.assertFalse(
            issue_detection._structured_result_is_bound(
                WorkflowEvidence(
                    **{**evidence.__dict__, "structured_result": missing_text}
                ),
                verifier,
            )
        )
        non_mapping = workflow_result_envelope("clean")
        non_mapping["payload"] = []
        self.assertFalse(
            issue_detection._structured_result_is_bound(
                WorkflowEvidence(
                    **{**evidence.__dict__, "structured_result": non_mapping}
                ),
                verifier,
            )
        )
        invalid_cause = workflow_result_envelope("operational_failure")
        invalid_cause["payload"]["cause_class"] = "invalid cause"
        self.assertFalse(
            issue_detection._structured_result_is_bound(
                WorkflowEvidence(
                    **{**evidence.__dict__, "structured_result": invalid_cause}
                ),
                verifier,
            )
        )

        class OpaquePayload(Mapping):
            def __init__(self):
                self.data = {
                    "schema": "appguardrail.workflow-result.v1",
                    "outcome": "clean",
                }

            def __getitem__(self, key):
                return self.data[key]

            def __iter__(self):
                return iter(self.data)

            def __len__(self):
                return len(self.data)

        opaque = workflow_result_envelope("clean")
        opaque["payload"] = OpaquePayload()
        self.assertFalse(
            issue_detection._structured_result_is_bound(
                WorkflowEvidence(
                    **{**evidence.__dict__, "structured_result": opaque}
                ),
                verifier,
            )
        )

    def test_every_historical_claim_executes_raw_three_way_evidence(self) -> None:
        """All 417 claims inherit raw positive, negative, and unknown evidence."""
        registry = load_issue_detection_registry()

        for target in registry.issues:
            for claim in target.claims:
                for fixture_name, expected_status in (
                    ("positive", "detected"),
                    ("negative", "clean"),
                    ("unknown", "unknown"),
                ):
                    with self.subTest(
                        issue=target.issue_number,
                        claim=claim.claim_id,
                        fixture=fixture_name,
                    ):
                        assessment = evaluate_issue_claim(
                            target.issue_number,
                            claim.claim_id,
                            materialize_issue_claim_fixture(
                                target.issue_number,
                                claim.claim_id,
                                fixture_name,
                                registry=registry,
                            ),
                            registry=registry,
                            workflow_result_verifier=workflow_result_verifier(),
                        )
                        self.assertEqual(assessment.status, expected_status)

    def test_fixture_claim_token_is_not_interpreted_in_runtime_evidence(self) -> None:
        """A literal fixture placeholder cannot assert that a claim is verified."""
        registry = load_issue_detection_registry()
        assessment = evaluate_issue_claim(
            132,
            "release-integrity",
            {
                "schema": "appguardrail.detector-evidence.product-security-audit.v1",
                "findings": [],
                "verified_controls": ["$claim_id"],
            },
            registry=registry,
        )

        self.assertEqual(assessment.status, "unknown")
        self.assertFalse(assessment.gate_satisfied)

    def test_unregistered_issue_and_claim_fail_closed(self) -> None:
        """Callers cannot invent issue or claim identities at evaluation time."""
        registry = load_issue_detection_registry()
        with self.assertRaisesRegex(ValueError, "unregistered issue number"):
            evaluate_issue_claim(999, "missing", {}, registry=registry)
        with self.assertRaisesRegex(ValueError, "unregistered issue claim"):
            evaluate_issue_claim(132, "missing", {}, registry=registry)
        with self.assertRaisesRegex(ValueError, "unregistered issue number"):
            materialize_issue_claim_fixture(
                999,
                "missing",
                "positive",
                registry=registry,
            )
        with self.assertRaisesRegex(ValueError, "unregistered issue claim"):
            materialize_issue_claim_fixture(
                132,
                "missing",
                "positive",
                registry=registry,
            )
        with self.assertRaisesRegex(ValueError, "unregistered issue fixture"):
            materialize_issue_claim_fixture(
                132,
                "release-integrity",
                "missing",
                registry=registry,
            )
        malformed = evaluate_issue_claim(
            132,
            "release-integrity",
            [],
            registry=registry,
        )
        self.assertEqual(malformed.status, "unknown")

    def test_unknown_detector_family_is_explicitly_unregistered(self) -> None:
        """A new job or family cannot silently inherit the native detector."""
        self.assertEqual(
            detector_family_for_job("future-security-engine"),
            "unregistered",
        )
        self.assertEqual(
            detector_family_for_job("future-strix-security-engine"),
            "unregistered",
        )
        with self.assertRaisesRegex(ValueError, "unregistered detector family"):
            evaluate_detector_family("future-security-engine", {})

    def test_live_inventory_audit_reports_new_and_stale_requirements(self) -> None:
        """A newly opened issue cannot silently escape the detector registry."""
        registry = load_issue_detection_registry()
        live = [
            target.issue_number
            for target in registry.issues
            if target.issue_number != 536
        ]
        live.append(999)

        audit = audit_issue_coverage(live, registry)

        self.assertEqual(audit.unmapped_issue_numbers, (999,))
        self.assertEqual(audit.registry_only_issue_numbers, (536,))
        self.assertFalse(audit.complete)

    def test_registry_loader_rejects_waivers_and_broken_identity_sets(self) -> None:
        """No issue may be waived, duplicated, or mapped to an unknown detector."""
        source = Path(__file__).parents[1] / "appguardrail_core"
        payload = json.loads(
            (source / "issue_detection_registry.json").read_text(encoding="utf-8")
        )

        invalid_payloads = []
        waived = json.loads(json.dumps(payload))
        waived["issues"][0]["waiver"] = True
        invalid_payloads.append((waived, "forbidden registry field"))
        duplicate = json.loads(json.dumps(payload))
        duplicate["issues"][1]["issue_number"] = duplicate["issues"][0][
            "issue_number"
        ]
        invalid_payloads.append((duplicate, "strictly increasing"))
        unknown = json.loads(json.dumps(payload))
        unknown["issues"][0]["claims"][0]["detector_family"] = "not-implemented"
        invalid_payloads.append((unknown, "unknown detector family"))
        wrong_adapter = json.loads(json.dumps(payload))
        wrong_adapter["detector_families"][
            "product-security-audit-controls"
        ]["adapter_ref"] = "appguardrail_core.issue_detection:_openssf_adapter"
        invalid_payloads.append((wrong_adapter, "callable adapter reference"))
        answer_fixture = json.loads(json.dumps(payload))
        answer_fixture["detector_families"][
            "product-security-audit-controls"
        ]["fixtures"]["positive"]["state"] = "detected"
        invalid_payloads.append((answer_fixture, "raw evidence fixtures"))
        open_obligation = json.loads(json.dumps(payload))
        open_obligation["detector_families"][
            "product-security-audit-controls"
        ]["obligations"][0]["fixtures"]["positive_patch"][
            "unsupported_future_field"
        ] = True
        invalid_payloads.append((open_obligation, "executable obligations"))
        non_mapping_obligation = json.loads(json.dumps(payload))
        non_mapping_obligation["detector_families"][
            "product-security-audit-controls"
        ]["obligations"][0] = []
        invalid_payloads.append(
            (non_mapping_obligation, "executable obligations")
        )
        extra_obligation_key = json.loads(json.dumps(payload))
        extra_obligation_key["detector_families"][
            "product-security-audit-controls"
        ]["obligations"][0]["future"] = True
        invalid_payloads.append((extra_obligation_key, "executable obligations"))
        invalid_obligation = json.loads(json.dumps(payload))
        invalid_obligation["detector_families"][
            "product-security-audit-controls"
        ]["obligations"][0]["obligation_id"] = ""
        invalid_payloads.append((invalid_obligation, "executable obligations"))
        incomplete_schema = json.loads(json.dumps(payload))
        incomplete_schema["detector_families"][
            "product-security-audit-controls"
        ]["required_evidence_fields"].remove("schema")
        invalid_payloads.append((incomplete_schema, "closed evidence"))

        with TemporaryDirectory() as directory:
            for index, (invalid, message) in enumerate(invalid_payloads):
                with self.subTest(message=message):
                    path = Path(directory) / f"invalid-{index}.json"
                    path.write_text(json.dumps(invalid), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, message):
                        load_issue_detection_registry(path)

    def test_requirement_audit_fails_closed_for_missing_evidence(self) -> None:
        """A live identity without one stable title/body digest is incomplete."""
        registry = load_issue_detection_registry()
        requirements = {
            target.issue_number: target.requirement_sha256
            for target in registry.issues
        }
        requirements[132] = None

        audit = audit_issue_requirements(requirements, registry)

        self.assertEqual(audit.incomplete_issue_numbers, (132,))
        self.assertFalse(audit.complete)
        self.assertEqual(
            compute_issue_requirement_sha256("Title\r\n", "Body\r\n"),
            compute_issue_requirement_sha256("Title", "Body"),
        )
        self.assertEqual(
            len(compute_issue_requirement_sha256("\ud800", "requirement")),
            64,
        )


class IssueDetectionCommandTests(unittest.TestCase):
    """Expose the issue-derived detector and live registry audit as software."""

    def test_classify_workflow_command_emits_secret_safe_json(self) -> None:
        """The installed command classifies evidence without echoing source logs."""
        stdout = StringIO()
        stdin = StringIO(
            "REQUEST_CHANGES: confirmed password=do-not-publish\n"
            "Resource not accessible by integration (HTTP 403)\n"
        )

        exit_code = main(
            [
                "classify-workflow",
                "--workflow-name",
                "OpenCode Review Dispatch",
                "--job-name",
                "opencode-review",
                "--conclusion",
                "failure",
                "--log-file",
                "-",
            ],
            stdin=stdin,
            stdout=stdout,
        )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(len(payload["detections"]), 2)
        self.assertNotIn("do-not-publish", stdout.getvalue())

    def test_classify_workflow_command_reads_an_authorized_file(self) -> None:
        """The command accepts an authorized log file or standard input."""
        stdout = StringIO()

        with TemporaryDirectory() as directory:
            log_path = Path(directory) / "job.log"
            log_path.write_text("Vulnerabilities 2\n", encoding="utf-8")
            exit_code = main(
                [
                    "classify-workflow",
                    "--workflow-name",
                    "Strix Security Scan",
                    "--job-name",
                    "strix",
                    "--conclusion",
                    "failure",
                    "--log-file",
                    str(log_path),
                ],
                stdout=stdout,
            )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(
            payload["detections"][0]["detector_id"],
            "scanner.vulnerability_count_observed",
        )

    def test_classify_command_accepts_a_bound_structured_result(self) -> None:
        """The CLI confirms a result only when run and head provenance match."""
        stdout = StringIO()
        result = workflow_result_envelope(
            "finding",
            detector_id="strix.confirmed-finding",
            rule_id="confirmed-finding",
        )

        with TemporaryDirectory() as directory:
            result_path = Path(directory) / "result.json"
            result_path.write_text(json.dumps(result), encoding="utf-8")
            encoded_key = base64.b64encode(ATTESTATION_SECRET).decode("ascii")
            with patch.dict(
                os.environ,
                {"APPGUARDRAIL_WORKFLOW_RESULT_HMAC_KEY": encoded_key},
            ):
                exit_code = main(
                    [
                        "classify-workflow",
                        "--workflow-name",
                        "Strix Security Scan",
                        "--job-name",
                        "strix",
                        "--conclusion",
                        "failure",
                        "--run-id",
                        "run-1",
                        "--head-sha",
                        "a" * 40,
                        "--result-file",
                        str(result_path),
                    ],
                    stdin=StringIO(""),
                    stdout=stdout,
                )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertTrue(
            payload["detections"][0]["confirmed_security_finding"]
        )

    def test_classify_command_rejects_malformed_environment_key(self) -> None:
        """Untrusted result JSON cannot compensate for invalid runner key material."""
        stdout = StringIO()
        result = workflow_result_envelope("clean")

        with TemporaryDirectory() as directory:
            result_path = Path(directory) / "result.json"
            result_path.write_text(json.dumps(result), encoding="utf-8")
            with patch.dict(
                os.environ,
                {"APPGUARDRAIL_WORKFLOW_RESULT_HMAC_KEY": "not base64!"},
            ):
                exit_code = main(
                    [
                        "classify-workflow",
                        "--workflow-name",
                        "Strix Security Scan",
                        "--job-name",
                        "strix",
                        "--conclusion",
                        "success",
                        "--run-id",
                        "run-1",
                        "--head-sha",
                        "a" * 40,
                        "--result-file",
                        str(result_path),
                    ],
                    stdin=StringIO(""),
                    stdout=stdout,
                )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(
            payload["detections"][0]["detector_id"],
            "workflow.structured_result_invalid",
        )
        self.assertFalse(payload["detections"][0]["gate_satisfied"])

    def test_issue_payload_helpers_fail_closed_for_missing_conflicting_digest(
        self,
    ) -> None:
        """Duplicate or incomplete live issue records retain identity but no proof."""
        payload = [
            {"number": 132},
            {"number": 132, "title": "changed", "body": "changed"},
        ]

        requirements = issue_detection._issue_requirements_from_github_payload(
            payload
        )
        numbers = issue_detection._issue_numbers_from_github_payload(payload)

        self.assertEqual(requirements, {132: None})
        self.assertEqual(numbers, (132,))

    def test_audit_registry_command_filters_pull_requests_and_passes(self) -> None:
        """GitHub's issues endpoint may include PRs, which are not issue contracts."""
        registry = load_issue_detection_registry()
        issue_payload = [
            {
                "number": target.issue_number,
                "requirement_sha256": target.requirement_sha256,
            }
            for target in registry.issues
        ]
        issue_payload[0] = {
            "issue_number": issue_payload[0]["number"],
            "requirement_sha256": issue_payload[0]["requirement_sha256"],
            "url": "https://github.com/ContextualWisdomLab/appguardrail/issues/132",
        }
        issue_payload.append({"number": 999, "pull_request": {"url": "example"}})
        issue_payload.append(
            {
                "issue_number": 900,
                "url": "https://github.com/ContextualWisdomLab/appguardrail/pull/900",
            }
        )
        stdout = StringIO()

        with TemporaryDirectory() as directory:
            inventory = Path(directory) / "issues.json"
            inventory.write_text(
                json.dumps({"pages": [issue_payload], "ignored": "metadata"}),
                encoding="utf-8",
            )
            exit_code = main(
                ["audit-registry", "--issues-file", str(inventory)],
                stdout=stdout,
            )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["live_issue_count"], 414)
        self.assertTrue(payload["complete"])

    def test_audit_registry_command_fails_closed_for_new_issue(self) -> None:
        """A newly opened issue produces a failing, machine-readable audit."""
        registry = load_issue_detection_registry()
        issue_payload = [
            {
                "number": target.issue_number,
                "requirement_sha256": target.requirement_sha256,
            }
            for target in registry.issues
        ]
        issue_payload.append({"number": 999, "requirement_sha256": "0" * 64})
        stdout = StringIO()

        with TemporaryDirectory() as directory:
            inventory = Path(directory) / "issues.json"
            inventory.write_text(json.dumps(issue_payload), encoding="utf-8")
            exit_code = main(
                ["audit-registry", "--issues-file", str(inventory)],
                stdout=stdout,
            )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["unmapped_issue_numbers"], [999])
        self.assertFalse(payload["complete"])

    def test_audit_registry_command_detects_edited_requirement(self) -> None:
        """Changing issue title/body invalidates its retained claim digest."""
        registry = load_issue_detection_registry()
        issue_payload = [
            {
                "number": target.issue_number,
                "requirement_sha256": target.requirement_sha256,
            }
            for target in registry.issues
        ]
        issue_payload[0] = {
            "number": 132,
            "title": "edited requirement",
            "body": "new independently detectable claim",
            "requirement_sha256": registry.issues[0].requirement_sha256,
        }
        stdout = StringIO()

        with TemporaryDirectory() as directory:
            inventory = Path(directory) / "issues.json"
            inventory.write_text(json.dumps(issue_payload), encoding="utf-8")
            exit_code = main(
                ["audit-registry", "--issues-file", str(inventory)],
                stdout=stdout,
            )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["changed_issue_numbers"], [132])
        self.assertFalse(payload["complete"])
