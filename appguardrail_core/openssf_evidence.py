"""Collect conservative OpenSSF Best Practices evidence from official JSON APIs.

The module keeps network transport, payload interpretation, normalized finding
creation, and CLI serialization in one dependency-free vertical. Evidence that
cannot be observed or trusted remains explicit; it never becomes a claim that a
project is unregistered or has earned a badge.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CURRENT_ORIGIN = "https://www.bestpractices.dev"
LEGACY_ORIGIN = "https://bestpractices.coreinfrastructure.org"
ALLOWED_ORIGINS = frozenset({CURRENT_ORIGIN, LEGACY_ORIGIN})
BADGE_LEVELS = frozenset({"in_progress", "passing", "silver", "gold"})
EVIDENCE_STATUSES = BADGE_LEVELS | frozenset(
    {"unavailable", "malformed", "permission_limited"}
)
MAX_RESPONSE_BYTES = 1_000_000
DEFAULT_TIMEOUT_SECONDS = 15.0
USER_AGENT = "appguardrail-openssf-evidence/1"
API_DOCUMENTATION_URL = (
    "https://github.com/ossf/best-practices-badge/blob/main/docs/api.md"
)
ATTRIBUTION = "OpenSSF Best Practices badge contributors"
CONTENT_LICENSE = (
    "CDLA-Permissive-2.0 for public non-code content added or edited after "
    "2024-08-23; earlier contributions CC-BY-3.0 or CC-BY-3.0+"
)
CONTENT_LICENSE_POLICY_URL = f"{CURRENT_ORIGIN}/en"
_UTC_TIMESTAMP_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject redirects so fixed-origin evidence collection cannot be retargeted."""

    def redirect_request(
        self,
        req: object,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        """Return no redirected request, causing urllib to expose the 3xx response."""
        del req, fp, code, msg, headers, newurl
        return None


@dataclass(frozen=True)
class OpenSSFEvidence:
    """One auditable OpenSSF Best Practices verification outcome."""

    status: str
    repository_url: str
    verified_at: str
    badge_tier: str = ""
    evidence_url: str = ""
    project_id: int | None = None
    tiered_percentage: int | None = None
    source_origin: str = ""
    reason: str = ""


def _utc_timestamp() -> str:
    """Return the current UTC timestamp in stable second-precision form."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize_repository_url(value: str) -> str:
    """Validate and normalize the exact repository URL used for public lookup."""
    repository_url = str(value or "").strip()
    parsed = urllib.parse.urlsplit(repository_url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("repository URL must use http or https")
    if not parsed.hostname:
        raise ValueError("repository URL must include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("repository URL must not include credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("repository URL must not include a query or fragment")
    return repository_url.rstrip("/")


def _normalize_source_origin(value: str) -> str:
    """Return one exact official OpenSSF Best Practices service origin."""
    source_origin = str(value or "").strip().rstrip("/")
    if source_origin not in ALLOWED_ORIGINS:
        raise ValueError("source origin must be an official OpenSSF origin")
    return source_origin


def _normalize_verified_at(value: str | None) -> str:
    """Require one canonical UTC audit timestamp for every evidence outcome."""
    verified_at = str(value or "").strip()
    if not _UTC_TIMESTAMP_RE.fullmatch(verified_at):
        raise ValueError(
            "verified_at must use UTC second precision: YYYY-MM-DDTHH:MM:SSZ"
        )
    try:
        datetime.strptime(verified_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError(
            "verified_at must use UTC second precision: YYYY-MM-DDTHH:MM:SSZ"
        ) from exc
    return verified_at


def _non_affirmative_evidence(
    status: str,
    *,
    repository_url: str,
    verified_at: str,
    source_origin: str,
    reason: str,
) -> OpenSSFEvidence:
    """Build a bounded evidence record without a badge assertion."""
    return OpenSSFEvidence(
        status=status,
        repository_url=repository_url,
        verified_at=verified_at,
        source_origin=source_origin,
        reason=reason,
    )


def _project_matches_repository(project: dict[str, Any], repository_url: str) -> bool:
    """Return whether the official result carries the queried URL identity."""
    for field in ("repo_url", "homepage_url"):
        candidate = project.get(field)
        if not isinstance(candidate, str) or not candidate.strip():
            continue
        try:
            normalized_candidate = _normalize_repository_url(candidate)
        except ValueError:
            continue
        if normalized_candidate == repository_url:
            return True
    return False


def parse_project_matches(
    payload: Any,
    *,
    repository_url: str,
    verified_at: str,
    source_origin: str,
) -> OpenSSFEvidence:
    """Interpret one official exact-URL project search response conservatively.

    The OpenSSF endpoint returns an array. A single valid object can establish a
    badge state; an empty array establishes only that no matching public evidence
    was observed. Every ambiguous or unsupported shape becomes ``malformed``.
    """
    normalized_repository = _normalize_repository_url(repository_url)
    normalized_origin = _normalize_source_origin(source_origin)
    normalized_timestamp = _normalize_verified_at(verified_at)

    if not isinstance(payload, list):
        return _non_affirmative_evidence(
            "malformed",
            repository_url=normalized_repository,
            verified_at=normalized_timestamp,
            source_origin=normalized_origin,
            reason="payload_not_array",
        )
    if not payload:
        return _non_affirmative_evidence(
            "unavailable",
            repository_url=normalized_repository,
            verified_at=normalized_timestamp,
            source_origin=normalized_origin,
            reason="no_matching_public_project",
        )
    if len(payload) != 1:
        return _non_affirmative_evidence(
            "malformed",
            repository_url=normalized_repository,
            verified_at=normalized_timestamp,
            source_origin=normalized_origin,
            reason="ambiguous_match_count",
        )

    project = payload[0]
    if not isinstance(project, dict):
        return _non_affirmative_evidence(
            "malformed",
            repository_url=normalized_repository,
            verified_at=normalized_timestamp,
            source_origin=normalized_origin,
            reason="project_not_object",
        )

    project_id = project.get("id")
    if (
        not isinstance(project_id, int)
        or isinstance(project_id, bool)
        or project_id <= 0
    ):
        return _non_affirmative_evidence(
            "malformed",
            repository_url=normalized_repository,
            verified_at=normalized_timestamp,
            source_origin=normalized_origin,
            reason="invalid_project_id",
        )

    badge_level = str(project.get("badge_level") or "").strip().lower()
    if badge_level not in BADGE_LEVELS:
        return _non_affirmative_evidence(
            "malformed",
            repository_url=normalized_repository,
            verified_at=normalized_timestamp,
            source_origin=normalized_origin,
            reason="unknown_badge_level",
        )

    tiered_percentage = project.get("tiered_percentage")
    if tiered_percentage is not None and (
        not isinstance(tiered_percentage, int)
        or isinstance(tiered_percentage, bool)
        or tiered_percentage < 0
        or tiered_percentage > 300
    ):
        return _non_affirmative_evidence(
            "malformed",
            repository_url=normalized_repository,
            verified_at=normalized_timestamp,
            source_origin=normalized_origin,
            reason="invalid_tiered_percentage",
        )

    if not _project_matches_repository(project, normalized_repository):
        return _non_affirmative_evidence(
            "malformed",
            repository_url=normalized_repository,
            verified_at=normalized_timestamp,
            source_origin=normalized_origin,
            reason="project_url_mismatch",
        )

    return OpenSSFEvidence(
        status=badge_level,
        repository_url=normalized_repository,
        verified_at=normalized_timestamp,
        badge_tier=badge_level,
        evidence_url=f"{CURRENT_ORIGIN}/projects/{project_id}",
        project_id=project_id,
        tiered_percentage=tiered_percentage,
        source_origin=normalized_origin,
    )


parse_openssf_project_matches = parse_project_matches


def _validated_evidence(evidence: OpenSSFEvidence) -> OpenSSFEvidence:
    """Validate public dataclass construction against the parser's trust boundary."""
    if evidence.status not in EVIDENCE_STATUSES:
        raise ValueError("unsupported OpenSSF evidence status")
    repository_url = _normalize_repository_url(evidence.repository_url)
    verified_at = _normalize_verified_at(evidence.verified_at)
    source_origin = _normalize_source_origin(evidence.source_origin)
    tiered_percentage = evidence.tiered_percentage
    if tiered_percentage is not None and (
        not isinstance(tiered_percentage, int)
        or isinstance(tiered_percentage, bool)
        or tiered_percentage < 0
        or tiered_percentage > 300
    ):
        raise ValueError("tiered percentage must be an integer from 0 through 300")

    if evidence.status in BADGE_LEVELS:
        if evidence.badge_tier != evidence.status:
            raise ValueError("badge tier must match the affirmative evidence status")
        if (
            not isinstance(evidence.project_id, int)
            or isinstance(evidence.project_id, bool)
            or evidence.project_id <= 0
        ):
            raise ValueError("project id must be a positive integer")
        expected_url = f"{CURRENT_ORIGIN}/projects/{evidence.project_id}"
        if evidence.evidence_url != expected_url:
            raise ValueError("evidence URL must be the canonical public project URL")
        if evidence.reason:
            raise ValueError("affirmative evidence must not contain a failure reason")
    else:
        if (
            evidence.badge_tier
            or evidence.evidence_url
            or evidence.project_id is not None
            or tiered_percentage is not None
        ):
            raise ValueError(
                "non-affirmative evidence cannot carry affirmative badge metadata"
            )
        if not evidence.reason:
            raise ValueError("non-affirmative evidence must include an evidence reason")

    return OpenSSFEvidence(
        status=evidence.status,
        repository_url=repository_url,
        verified_at=verified_at,
        badge_tier=evidence.badge_tier,
        evidence_url=evidence.evidence_url,
        project_id=evidence.project_id,
        tiered_percentage=tiered_percentage,
        source_origin=source_origin,
        reason=evidence.reason,
    )


def _status_message(evidence: OpenSSFEvidence) -> str:
    """Return conservative buyer-facing prose for one evidence state."""
    if evidence.status in BADGE_LEVELS:
        tier = evidence.badge_tier.replace("_", " ")
        return (
            "OpenSSF Best Practices badge evidence was verified at the "
            f"{tier} level for {evidence.repository_url}."
        )
    if evidence.status == "unavailable":
        return (
            "No matching public OpenSSF Best Practices evidence was observed at "
            "verification time; this does not prove non-registration."
        )
    if evidence.status == "permission_limited":
        return (
            "OpenSSF Best Practices evidence could not be verified because the "
            "service returned a permission-limited response."
        )
    if evidence.status == "malformed":
        return (
            "The OpenSSF Best Practices service returned malformed or ambiguous "
            "evidence, so no badge claim was made."
        )
    raise ValueError("unsupported OpenSSF evidence status")


def _status_remediation(evidence: OpenSSFEvidence) -> str:
    """Return one evidence-appropriate operator action."""
    if evidence.status in BADGE_LEVELS:
        return (
            "Retain the evidence URL and verification timestamp with release and "
            "buyer-diligence artifacts; re-verify periodically for drift."
        )
    if evidence.status == "unavailable":
        return (
            "Verify the exact repository URL in the OpenSSF Best Practices service "
            "and collect a project URL if public evidence exists."
        )
    if evidence.status == "permission_limited":
        return (
            "Retry the public JSON lookup after confirming service access; do not "
            "substitute a badge assertion without verifiable evidence."
        )
    return (
        "Inspect the saved service response, resolve malformed or ambiguous project "
        "evidence, and repeat the exact repository URL lookup."
    )


def evidence_to_finding(evidence: OpenSSFEvidence) -> dict[str, Any]:
    """Convert one evidence record into a normalized governance finding."""
    evidence = _validated_evidence(evidence)
    references = [
        CURRENT_ORIGIN,
        API_DOCUMENTATION_URL,
        CONTENT_LICENSE_POLICY_URL,
    ]
    if evidence.evidence_url:
        references.append(evidence.evidence_url)
    remediation = _status_remediation(evidence)
    return {
        "rule_id": "openssf-best-practices-evidence",
        "severity": "INFO" if evidence.status in BADGE_LEVELS else "WARNING",
        "message": _status_message(evidence),
        "file": "OpenSSF Best Practices API",
        "line": 1,
        "snippet": "",
        "source": "openssf-best-practices",
        "attribution": ATTRIBUTION,
        "content_license": CONTENT_LICENSE,
        "content_license_policy_url": CONTENT_LICENSE_POLICY_URL,
        "category": "supply-chain",
        "confidence": "high" if evidence.status in BADGE_LEVELS else "medium",
        "context": "governance",
        "remediation": remediation,
        "fix_prompt": remediation,
        "verification": (
            "Repeat the official exact repository URL JSON lookup and retain the "
            "response timestamp with the resulting evidence."
        ),
        "references": references,
        "owasp": [],
        "cwe": [],
        "evidence_status": evidence.status,
        "badge_tier": evidence.badge_tier,
        "evidence_url": evidence.evidence_url,
        "verified_at": evidence.verified_at,
        "project_id": evidence.project_id,
        "tiered_percentage": evidence.tiered_percentage,
        "repository_url": evidence.repository_url,
        "source_origin": evidence.source_origin,
        "evidence_reason": evidence.reason,
    }


def _project_search_url(origin: str, repository_url: str) -> str:
    """Build the official exact-URL JSON search endpoint."""
    query = urllib.parse.urlencode({"url": repository_url})
    return f"{origin}/projects.json?{query}"


def _is_json_media_type(value: Any) -> bool:
    """Return whether a Content-Type is JSON or a structured JSON subtype."""
    media_type = str(value or "").split(";", 1)[0].strip().lower()
    return media_type == "application/json" or (
        media_type.startswith("application/") and media_type.endswith("+json")
    )


def _fetch_origin(
    repository_url: str,
    *,
    verified_at: str,
    source_origin: str,
    opener: Any,
    timeout: float,
) -> OpenSSFEvidence:
    """Fetch and classify one official origin without leaking response bodies."""
    request = urllib.request.Request(  # noqa: S310 - origin is allowlisted
        _project_search_url(source_origin, repository_url),
        method="GET",
        headers={"User-Agent": USER_AGENT},
    )
    try:
        with opener.open(request, timeout=timeout) as response:  # noqa: S310
            if not _is_json_media_type(response.headers.get("content-type", "")):
                return _non_affirmative_evidence(
                    "malformed",
                    repository_url=repository_url,
                    verified_at=verified_at,
                    source_origin=source_origin,
                    reason="unexpected_content_type",
                )
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        try:
            if exc.code in {401, 403}:
                status = "permission_limited"
                reason = f"http_{exc.code}"
            elif 300 <= exc.code < 400:
                status = "malformed"
                reason = "unexpected_redirect"
            else:
                status = "unavailable"
                reason = f"http_{exc.code}"
        finally:
            exc.close()
        return _non_affirmative_evidence(
            status,
            repository_url=repository_url,
            verified_at=verified_at,
            source_origin=source_origin,
            reason=reason,
        )
    except TimeoutError:
        return _non_affirmative_evidence(
            "unavailable",
            repository_url=repository_url,
            verified_at=verified_at,
            source_origin=source_origin,
            reason="timeout",
        )
    except urllib.error.URLError as exc:
        reason = "timeout" if isinstance(exc.reason, TimeoutError) else "network_error"
        return _non_affirmative_evidence(
            "unavailable",
            repository_url=repository_url,
            verified_at=verified_at,
            source_origin=source_origin,
            reason=reason,
        )
    except OSError:
        return _non_affirmative_evidence(
            "unavailable",
            repository_url=repository_url,
            verified_at=verified_at,
            source_origin=source_origin,
            reason="network_error",
        )

    if len(body) > MAX_RESPONSE_BYTES:
        return _non_affirmative_evidence(
            "malformed",
            repository_url=repository_url,
            verified_at=verified_at,
            source_origin=source_origin,
            reason="response_too_large",
        )
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return _non_affirmative_evidence(
            "malformed",
            repository_url=repository_url,
            verified_at=verified_at,
            source_origin=source_origin,
            reason="invalid_json",
        )
    return parse_project_matches(
        payload,
        repository_url=repository_url,
        verified_at=verified_at,
        source_origin=source_origin,
    )


def collect_openssf_evidence(
    repository_url: str,
    *,
    verified_at: str | None = None,
    opener: Any | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> OpenSSFEvidence:
    """Collect current, then eligible historical, evidence for one repository."""
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or timeout <= 0
    ):
        raise ValueError("timeout must be a positive number")
    normalized_repository = _normalize_repository_url(repository_url)
    timestamp = _normalize_verified_at(
        verified_at if verified_at is not None else _utc_timestamp()
    )
    client = opener if opener is not None else urllib.request.build_opener(NoRedirect())
    current = _fetch_origin(
        normalized_repository,
        verified_at=timestamp,
        source_origin=CURRENT_ORIGIN,
        opener=client,
        timeout=float(timeout),
    )
    if not (
        current.status == "unavailable"
        and current.reason == "no_matching_public_project"
    ):
        return current

    historical = _fetch_origin(
        normalized_repository,
        verified_at=timestamp,
        source_origin=LEGACY_ORIGIN,
        opener=client,
        timeout=float(timeout),
    )
    if (
        historical.status == "unavailable"
        and historical.reason == "no_matching_public_project"
    ):
        return OpenSSFEvidence(
            status="unavailable",
            repository_url=normalized_repository,
            verified_at=timestamp,
            source_origin=LEGACY_ORIGIN,
            reason="no_matching_public_project_current_or_legacy",
        )
    return historical


def findings_envelope(evidence: OpenSSFEvidence) -> dict[str, Any]:
    """Return the standard AppGuardrail findings envelope for one evidence record."""
    return {
        "schema": "appguardrail.findings.v1",
        "findings": [evidence_to_finding(evidence)],
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse live or offline evidence-collection arguments."""
    parser = argparse.ArgumentParser(
        prog="appguardrail-openssf-evidence",
        description="Collect auditable OpenSSF Best Practices evidence.",
    )
    parser.add_argument("--repository-url", required=True)
    parser.add_argument("--source-json")
    parser.add_argument(
        "--source-origin",
        choices=sorted(ALLOWED_ORIGINS),
        default=CURRENT_ORIGIN,
    )
    parser.add_argument("--verified-at")
    parser.add_argument("--out")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Collect or ingest evidence and emit one normalized findings envelope."""
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        timestamp = _normalize_verified_at(args.verified_at or _utc_timestamp())
        if args.source_json:
            source_path = Path(args.source_json)
            try:
                with source_path.open("rb") as source_file:
                    source_bytes = source_file.read(MAX_RESPONSE_BYTES + 1)
            except OSError:
                print(
                    f"Cannot read OpenSSF evidence source: {source_path}",
                    file=sys.stderr,
                )
                return 1
            if len(source_bytes) > MAX_RESPONSE_BYTES:
                print(
                    f"OpenSSF evidence source exceeds {MAX_RESPONSE_BYTES} bytes: {source_path}",
                    file=sys.stderr,
                )
                return 1
            try:
                payload = json.loads(source_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                print(
                    "OpenSSF evidence source contains invalid JSON or UTF-8: "
                    f"{source_path}",
                    file=sys.stderr,
                )
                return 1
            record = parse_project_matches(
                payload,
                repository_url=args.repository_url,
                verified_at=timestamp,
                source_origin=args.source_origin,
            )
        else:
            record = collect_openssf_evidence(
                args.repository_url,
                verified_at=timestamp,
            )
    except ValueError as exc:
        print(f"Invalid OpenSSF evidence input: {exc}", file=sys.stderr)
        return 1

    rendered = json.dumps(findings_envelope(record), indent=2, sort_keys=True) + "\n"
    if args.out:
        target = Path(args.out)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(rendered, encoding="utf-8")
        except OSError:
            print(f"Cannot write OpenSSF evidence output: {target}", file=sys.stderr)
            return 1
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through runpy contract
    raise SystemExit(main())
