"""Regression tests for security-failure diagnosis guidance."""

from appguardrail_core import issueops


def test_action_required_diagnosis_requires_authorized_review():
    """Protected-action failures must require an authorized human review."""
    text = issueops.diagnosis(
        {
            "workflow": "CodeQL",
            "job_name": "Analyze",
            "conclusion": "action_required",
        }
    )

    assert "authorized maintainer" in text
    assert "reviewing the triggering changes" in text
    assert "rerun the exact head commit" in text


def test_cancelled_diagnosis_requires_a_conclusive_rerun():
    """Cancelled security gates must not be treated as successful evidence."""
    text = issueops.diagnosis(
        {
            "workflow": "Security Scan",
            "job_name": "scan",
            "conclusion": "cancelled",
        }
    )

    assert "who or what cancelled the run" in text
    assert "conclusive result" in text


def test_codeql_pending_receiver_diagnosis_routes_to_canonical_settlement_owner():
    """A pending delegated verdict must not be presented as a leaf source finding."""
    text = issueops.diagnosis(
        {
            "workflow": "CodeQL PR",
            "job_name": "CodeQL compatibility analysis (python)",
            "conclusion": "failure",
            "snippet": (
                "VERDICT_STATE: pending\n"
                "::error::CodeQL scan dispatched. The dispatch workflow will rerun "
                "this exact failed CodeQL job after publishing its terminal verdict."
            ),
        }
    )

    assert "does not establish a source-code security finding" in text
    assert "canonical `.github` CodeQL producer" in text
    assert "same repository, PR, base, head, language, and required run/job" in text
    assert "Do not broadly rerun" in text


def test_generic_codeql_failure_does_not_claim_a_settlement_ordering_defect():
    """Other CodeQL failures retain the evidence-neutral security diagnosis."""
    text = issueops.diagnosis(
        {
            "workflow": "CodeQL PR",
            "job_name": "CodeQL compatibility analysis (python)",
            "conclusion": "failure",
            "snippet": (
                'echo "::error::CodeQL scan dispatched. The dispatch workflow will '
                'rerun this exact failed CodeQL job after publishing its terminal verdict."\n'
                "VERDICT_STATE: failure\n"
                "##[error]CodeQL dispatch scan for python did not pass (state=failure)."
            ),
        }
    )

    assert "does not establish a source-code security finding" not in text
    assert "canonical `.github` CodeQL producer" not in text
