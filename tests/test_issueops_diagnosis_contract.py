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
