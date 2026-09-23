"""Core contracts for conservative OpenSSF Best Practices evidence."""

from __future__ import annotations

import pytest

from appguardrail_core.openssf_evidence import (
    CURRENT_ORIGIN,
    LEGACY_ORIGIN,
    OpenSSFEvidence,
    evidence_to_finding,
    parse_project_matches,
)


VERIFIED_AT = "2026-08-04T06:30:00Z"
REPOSITORY_URL = "https://github.com/ContextualWisdomLab/appguardrail"


def _project(level: str, **overrides: object) -> dict[str, object]:
    """Return one official-project-shaped payload with controlled overrides."""
    project: dict[str, object] = {
        "id": 865,
        "badge_level": level,
        "tiered_percentage": 200,
        "repo_url": REPOSITORY_URL,
    }
    project.update(overrides)
    return project


@pytest.mark.parametrize("level", ["in_progress", "passing", "silver", "gold"])
def test_parse_project_matches_preserves_supported_badge_level(level: str) -> None:
    """Every official badge level must remain explicit rather than inferred."""
    evidence = parse_project_matches(
        [_project(level)],
        repository_url=REPOSITORY_URL + "/",
        verified_at=VERIFIED_AT,
        source_origin=CURRENT_ORIGIN,
    )

    assert evidence == OpenSSFEvidence(
        status=level,
        repository_url=REPOSITORY_URL,
        verified_at=VERIFIED_AT,
        badge_tier=level,
        evidence_url=f"{CURRENT_ORIGIN}/projects/865",
        project_id=865,
        tiered_percentage=200,
        source_origin=CURRENT_ORIGIN,
        reason="",
    )


def test_homepage_url_can_prove_the_exact_query_identity() -> None:
    """The official URL search may match either repository or homepage identity."""
    evidence = parse_project_matches(
        [
            _project(
                "passing",
                repo_url="https://github.com/acme/different-repository",
                homepage_url=REPOSITORY_URL + "/",
            )
        ],
        repository_url=REPOSITORY_URL,
        verified_at=VERIFIED_AT,
        source_origin=CURRENT_ORIGIN,
    )

    assert evidence.status == "passing"
    assert evidence.repository_url == REPOSITORY_URL


def test_empty_search_is_unavailable_without_claiming_non_registration() -> None:
    """An empty public search result is absence of observed evidence, not proof."""
    evidence = parse_project_matches(
        [],
        repository_url=REPOSITORY_URL,
        verified_at=VERIFIED_AT,
        source_origin=LEGACY_ORIGIN,
    )

    assert evidence.status == "unavailable"
    assert evidence.badge_tier == ""
    assert evidence.project_id is None
    assert evidence.evidence_url == ""
    assert evidence.source_origin == LEGACY_ORIGIN
    assert evidence.reason == "no_matching_public_project"


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        ({"projects": []}, "payload_not_array"),
        ([_project("passing"), _project("gold", id=866)], "ambiguous_match_count"),
        (["not-an-object"], "project_not_object"),
        ([_project("passing", id=True)], "invalid_project_id"),
        ([_project("passing", id=0)], "invalid_project_id"),
        ([_project("platinum")], "unknown_badge_level"),
        ([_project("gold", tiered_percentage=True)], "invalid_tiered_percentage"),
        ([_project("gold", tiered_percentage=-1)], "invalid_tiered_percentage"),
        ([_project("gold", tiered_percentage=301)], "invalid_tiered_percentage"),
        (
            [_project("gold", repo_url="https://github.com/acme/other")],
            "project_url_mismatch",
        ),
        (
            [_project("gold", repo_url=None, homepage_url=None)],
            "project_url_mismatch",
        ),
    ],
)
def test_malformed_or_ambiguous_evidence_fails_closed(
    payload: object,
    reason: str,
) -> None:
    """Unsupported evidence shapes must be reported without guessing a badge state."""
    evidence = parse_project_matches(
        payload,
        repository_url=REPOSITORY_URL,
        verified_at=VERIFIED_AT,
        source_origin=CURRENT_ORIGIN,
    )

    assert evidence.status == "malformed"
    assert evidence.reason == reason
    assert evidence.badge_tier == ""
    assert evidence.project_id is None


def test_optional_tiered_percentage_may_be_absent() -> None:
    """The official tier is authoritative even when percentage detail is omitted."""
    evidence = parse_project_matches(
        [_project("silver", tiered_percentage=None)],
        repository_url=REPOSITORY_URL,
        verified_at=VERIFIED_AT,
        source_origin=CURRENT_ORIGIN,
    )

    assert evidence.status == "silver"
    assert evidence.tiered_percentage is None


@pytest.mark.parametrize(
    ("repository_url", "source_origin", "verified_at", "match"),
    [
        ("file:///tmp/repo", CURRENT_ORIGIN, VERIFIED_AT, "http or https"),
        (
            "https://user:secret@example.com/repo",
            CURRENT_ORIGIN,
            VERIFIED_AT,
            "credentials",
        ),
        ("https:///missing-host", CURRENT_ORIGIN, VERIFIED_AT, "host"),
        (REPOSITORY_URL, "https://attacker.invalid", VERIFIED_AT, "source origin"),
        (REPOSITORY_URL, CURRENT_ORIGIN, "", "verified_at"),
        (REPOSITORY_URL, CURRENT_ORIGIN, "2026-08-04", "verified_at"),
        (REPOSITORY_URL, CURRENT_ORIGIN, "2026-8-04T06:30:00Z", "verified_at"),
        (REPOSITORY_URL, CURRENT_ORIGIN, "2026-08-04T6:30:00Z", "verified_at"),
        (
            REPOSITORY_URL,
            CURRENT_ORIGIN,
            "2026-13-40T25:61:61Z",
            "verified_at",
        ),
    ],
)
def test_parser_rejects_unsafe_identity_inputs(
    repository_url: str,
    source_origin: str,
    verified_at: str,
    match: str,
) -> None:
    """Evidence identity must not carry unsafe URLs or invalid audit timestamps."""
    with pytest.raises(ValueError, match=match):
        parse_project_matches(
            [],
            repository_url=repository_url,
            verified_at=verified_at,
            source_origin=source_origin,
        )


@pytest.mark.parametrize(
    ("status", "severity"),
    [
        ("in_progress", "INFO"),
        ("passing", "INFO"),
        ("silver", "INFO"),
        ("gold", "INFO"),
        ("unavailable", "WARNING"),
        ("malformed", "WARNING"),
        ("permission_limited", "WARNING"),
    ],
)
def test_evidence_to_finding_preserves_auditable_metadata(
    status: str,
    severity: str,
) -> None:
    """Normalized findings must retain the evidence state used in buyer diligence."""
    badge_tier = status if status in {"in_progress", "passing", "silver", "gold"} else ""
    evidence = OpenSSFEvidence(
        status=status,
        repository_url=REPOSITORY_URL,
        verified_at=VERIFIED_AT,
        badge_tier=badge_tier,
        evidence_url=f"{CURRENT_ORIGIN}/projects/865" if badge_tier else "",
        project_id=865 if badge_tier else None,
        tiered_percentage=200 if badge_tier else None,
        source_origin=CURRENT_ORIGIN,
        reason="transport_or_payload_state" if not badge_tier else "",
    )

    finding = evidence_to_finding(evidence)

    assert finding["rule_id"] == "openssf-best-practices-evidence"
    assert finding["severity"] == severity
    assert finding["category"] == "supply-chain"
    assert finding["context"] == "governance"
    assert finding["source"] == "openssf-best-practices"
    assert finding["attribution"] == "OpenSSF Best Practices badge contributors"
    assert "CDLA-Permissive-2.0" in finding["content_license"]
    assert "CC-BY-3.0" in finding["content_license"]
    assert finding["content_license_policy_url"] == f"{CURRENT_ORIGIN}/en"
    assert finding["evidence_status"] == status
    assert finding["badge_tier"] == badge_tier
    assert finding["evidence_url"] == evidence.evidence_url
    assert finding["verified_at"] == VERIFIED_AT
    assert finding["project_id"] == evidence.project_id
    assert finding["tiered_percentage"] == evidence.tiered_percentage
    assert finding["repository_url"] == REPOSITORY_URL
    assert finding["source_origin"] == CURRENT_ORIGIN
    assert finding["evidence_reason"] == evidence.reason
    assert CURRENT_ORIGIN in finding["references"]
    assert f"{CURRENT_ORIGIN}/en" in finding["references"]

    if status == "unavailable":
        assert "does not prove" in finding["message"]
        assert "verify" in finding["remediation"].lower()
    elif status == "permission_limited":
        assert "permission" in finding["message"].lower()
    elif status == "malformed":
        assert "malformed" in finding["message"].lower()
    else:
        assert badge_tier.replace("_", " ") in finding["message"].lower()


def test_evidence_to_finding_rejects_unknown_internal_status() -> None:
    """Callers cannot silently publish a status outside the documented contract."""
    with pytest.raises(ValueError, match="status"):
        evidence_to_finding(
            OpenSSFEvidence(
                status="unknown",
                repository_url=REPOSITORY_URL,
                verified_at=VERIFIED_AT,
            )
        )


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"source_origin": ""}, "source origin"),
        ({"badge_tier": "silver"}, "badge tier"),
        ({"project_id": None}, "project id"),
        ({"evidence_url": "javascript:alert(1)"}, "evidence URL"),
        ({"reason": "unexpected"}, "reason"),
        ({"tiered_percentage": True}, "tiered percentage"),
    ],
)
def test_evidence_to_finding_rejects_inconsistent_affirmative_records(
    overrides: dict[str, object],
    match: str,
) -> None:
    """Public dataclass construction cannot bypass the parser's evidence boundary."""
    values: dict[str, object] = {
        "status": "gold",
        "repository_url": REPOSITORY_URL,
        "verified_at": VERIFIED_AT,
        "badge_tier": "gold",
        "evidence_url": f"{CURRENT_ORIGIN}/projects/865",
        "project_id": 865,
        "tiered_percentage": 300,
        "source_origin": CURRENT_ORIGIN,
        "reason": "",
    }
    values.update(overrides)

    with pytest.raises(ValueError, match=match):
        evidence_to_finding(OpenSSFEvidence(**values))


def test_evidence_to_finding_rejects_badged_non_affirmative_record() -> None:
    """Unavailable evidence cannot carry stale affirmative badge metadata."""
    with pytest.raises(ValueError, match="non-affirmative"):
        evidence_to_finding(
            OpenSSFEvidence(
                status="unavailable",
                repository_url=REPOSITORY_URL,
                verified_at=VERIFIED_AT,
                badge_tier="gold",
                evidence_url=f"{CURRENT_ORIGIN}/projects/865",
                project_id=865,
                tiered_percentage=300,
                source_origin=CURRENT_ORIGIN,
                reason="no_matching_public_project",
            )
        )
