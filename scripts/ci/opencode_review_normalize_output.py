#!/usr/bin/env python3
"""Normalize OpenCode review output into the strict approval-gate contract."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

STRUCTURAL_FAILURE_PHRASES = (
    "structural exploration was not possible",
    "structural exploration not possible",
    "structural exploration is not required",
    "structural exploration not required",
    "structural analysis is not required",
    "structural analysis not required",
    "structural review is not required",
    "structural review not required",
    "no structural exploration required",
    "no structural analysis required",
    "no structural review required",
    "structural exploration is unnecessary",
    "structural analysis is unnecessary",
    "structural review is unnecessary",
    "changed files could not be inspected",
    "source files could not be inspected",
    "required files could not be inspected",
    "could not access changed files",
    "could not access the changed files",
    "could not access source files",
    "could not access the source files",
    "could not access required files",
    "could not access required evidence",
    "evidence was truncated",
    "truncated evidence",
    "no changes detected",
    "no changes were detected",
    "no changes found",
    "no changes were found",
    "no files or changes were found",
    "no files or changes found",
    "no actionable changes to review",
    "no changes to review",
    "no changed files",
)

STRUCTURAL_FAILURE_PATTERNS = (
    re.compile(
        r"\b(?:could not|cannot|can't|unable to)\s+"
        r"(?:inspect|access|review)\s+(?:the\s+)?"
        r"(?:changed|source|required)\s+files?\b"
    ),
    re.compile(
        r"\b(?:changed|source|required)\s+files?\s+"
        r"(?:could not|cannot|can't|were not|was not)\s+"
        r"(?:be\s+)?(?:inspected|accessed|reviewed)\b"
    ),
    re.compile(
        r"\b(?:structural\s+(?:exploration|analysis|review))\s+"
        r"(?:was\s+)?(?:unavailable|incomplete|blocked|not possible)\b"
    ),
    re.compile(
        r"\bno\s+(?:files?\s+or\s+)?changes?\s+"
        r"(?:were\s+)?(?:detected|found|present)\b"
    ),
    re.compile(r"\bno\s+(?:actionable\s+)?changes?\s+to\s+review\b"),
    re.compile(r"\b(?:no|zero)\s+changed\s+files?\b"),
)

CHANGED_FILE_EVIDENCE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.@+-]+"
    r"|(?<![A-Za-z0-9_])[A-Za-z0-9_.-]+\."
    r"(?:py|js|jsx|ts|tsx|mjs|cjs|sh|bash|yml|yaml|json|jsonc|toml|lock|md|txt|css|scss|html|sql|go|rs|java|kt|swift|rb|php|cs|xml|ini|cfg)"
    r"(?![A-Za-z0-9_])"
    r"|(?<![A-Za-z0-9_])(?:Dockerfile|Makefile|README|LICENSE|AGENTS\.md)(?![A-Za-z0-9_])"
)

CHANGED_FILES_REVIEW_PATTERNS = (
    re.compile(r"\b(?:inspected|reviewed|checked)\s+(?:the\s+)?changed\s+files?\b"),
    re.compile(r"\bafter\s+(?:inspecting|reviewing|checking)\s+(?:the\s+)?changed\s+files?\b"),
)


def safe_changed_file_path(path: str) -> str | None:
    """Return a normalized relative changed-file path, or None if unsafe."""
    normalized = path.strip()
    if not normalized or normalized.startswith("/") or "\x00" in normalized:
        return None
    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return None
    return normalized


def changed_file_paths_from_evidence(evidence_text: str) -> list[str]:
    """Extract trusted changed-file paths from bounded review evidence."""
    paths: list[str] = []
    in_changed_files = False

    for line in evidence_text.splitlines():
        if line.startswith("## "):
            in_changed_files = line.strip() == "## Changed files"
            continue
        if not in_changed_files or not line.strip():
            continue

        fields = line.split("\t")
        if len(fields) < 2:
            continue
        status = fields[0]
        if status.startswith(("R", "C")) and len(fields) >= 3:
            candidate = fields[-1]
        elif status in {"A", "M", "D", "T", "U", "X", "B"}:
            candidate = fields[1]
        else:
            continue

        path = safe_changed_file_path(candidate)
        if path is not None and path not in paths:
            paths.append(path)

    for match in re.finditer(r"^diff --git a/(.+?) b/(.+)$", evidence_text, re.MULTILINE):
        candidate = match.group(2) if match.group(2) != "/dev/null" else match.group(1)
        path = safe_changed_file_path(candidate)
        if path is not None and path not in paths:
            paths.append(path)

    return paths


def admits_missing_structural_review(reason: str, summary: str) -> bool:
    """Return whether an approval admits it did not inspect required structure."""
    combined = f"{reason}\n{summary}".casefold()
    return any(phrase in combined for phrase in STRUCTURAL_FAILURE_PHRASES) or any(
        pattern.search(combined) for pattern in STRUCTURAL_FAILURE_PATTERNS
    )


def mentions_changed_file_evidence(reason: str, summary: str) -> bool:
    """Return whether an approval names at least one concrete changed file/path."""
    return bool(CHANGED_FILE_EVIDENCE_PATTERN.search(f"{reason}\n{summary}"))


def claims_changed_file_review(reason: str, summary: str) -> bool:
    """Return whether an approval says it inspected the changed files."""
    combined = f"{reason}\n{summary}".casefold()
    return any(pattern.search(combined) for pattern in CHANGED_FILES_REVIEW_PATTERNS)


def summary_with_changed_file_evidence(
    reason: str,
    summary: str,
    changed_file_paths: list[str],
) -> str | None:
    """Add bounded changed-file evidence when the model claims changed-file review."""
    if mentions_changed_file_evidence(reason, summary):
        return summary
    if not changed_file_paths or not claims_changed_file_review(reason, summary):
        return None

    shown_paths = ", ".join(changed_file_paths[:3])
    if len(changed_file_paths) > 3:
        shown_paths = f"{shown_paths}, ..."
    return f"{summary} Changed-file evidence: {shown_paths}."


def check_structural_approval(control_file: Path) -> int:
    """Validate an already-normalized control block before publishing approval."""
    try:
        value = json.loads(control_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read OpenCode control JSON: {exc}", file=sys.stderr)
        return 65

    if not isinstance(value, dict):
        print("NO_CONCLUSION", file=sys.stderr)
        return 4

    if value.get("result") == "APPROVE" and admits_missing_structural_review(
        str(value.get("reason", "")),
        str(value.get("summary", "")),
    ):
        print("NO_CONCLUSION", file=sys.stderr)
        return 4
    if value.get("result") == "APPROVE" and not mentions_changed_file_evidence(
        str(value.get("reason", "")),
        str(value.get("summary", "")),
    ):
        print("NO_CONCLUSION", file=sys.stderr)
        return 4

    return 0


def valid_control(
    value: Any,
    *,
    expected_head_sha: str,
    expected_run_id: str,
    expected_run_attempt: str,
    changed_file_paths: list[str] | None = None,
) -> dict[str, Any] | None:
    """Return a normalized control block when it matches the current run."""
    if not isinstance(value, dict):
        return None

    if value.get("head_sha") != expected_head_sha:
        return None
    if value.get("run_id") != expected_run_id:
        return None
    if value.get("run_attempt") != expected_run_attempt:
        return None

    result = value.get("result")
    if result not in {"APPROVE", "REQUEST_CHANGES"}:
        return None

    if not isinstance(value.get("reason"), str) or not value["reason"].strip():
        return None
    if not isinstance(value.get("summary"), str) or not value["summary"].strip():
        return None
    reason = value["reason"].strip()
    summary = value["summary"].strip()
    changed_file_paths = changed_file_paths or []

    findings = value.get("findings")
    if findings is None and result == "APPROVE":
        findings = []
    if not isinstance(findings, list):
        return None
    if result == "APPROVE" and findings:
        return None
    if result == "REQUEST_CHANGES" and not findings:
        return None
    if result == "APPROVE" and admits_missing_structural_review(reason, summary):
        return None
    if result == "APPROVE":
        amended_summary = summary_with_changed_file_evidence(reason, summary, changed_file_paths)
        if amended_summary is None:
            return None
        summary = amended_summary

    required_finding_fields = (
        "path",
        "severity",
        "title",
        "problem",
        "root_cause",
        "fix_direction",
        "regression_test_direction",
        "suggested_diff",
    )
    for finding in findings:
        if not isinstance(finding, dict):
            return None
        line = finding.get("line")
        if isinstance(line, bool) or not isinstance(line, int) or line <= 0:
            return None
        for field in required_finding_fields:
            if not isinstance(finding.get(field), str) or not finding[field].strip():
                return None

    return {
        "head_sha": value["head_sha"],
        "run_id": value["run_id"],
        "run_attempt": value["run_attempt"],
        "result": result,
        "reason": reason,
        "summary": summary,
        "findings": findings,
    }


def iter_json_objects(text: str) -> list[Any]:
    """Extract JSON objects from raw OpenCode output that may include prose."""
    decoder = json.JSONDecoder()
    values: list[Any] = []

    index = 0
    while True:
        index = text.find("{", index)
        if index == -1:
            break
        try:
            value, end = decoder.raw_decode(text, index)
            values.append(value)
            index = end
        except json.JSONDecodeError:
            index += 1

    return values


def main(argv: list[str]) -> int:
    """Run the normalizer CLI and write the publishable control block."""
    if len(argv) == 3 and argv[1] == "--check-structural-approval":
        return check_structural_approval(Path(argv[2]))

    if len(argv) not in {5, 6}:
        print(
            "usage: opencode_review_normalize_output.py "
            "<expected_head_sha> <expected_run_id> <expected_run_attempt> <output_file> [evidence_file]\n"
            "   or: opencode_review_normalize_output.py --check-structural-approval <control_json_file>",
            file=sys.stderr,
        )
        return 64

    evidence_file_arg = None
    if len(argv) == 6:
        expected_head_sha, expected_run_id, expected_run_attempt, output_file_arg, evidence_file_arg = argv[1:]
    else:
        expected_head_sha, expected_run_id, expected_run_attempt, output_file_arg = argv[1:]
    output_file = Path(output_file_arg)
    changed_file_paths: list[str] = []

    try:
        output_text = output_file.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"cannot read OpenCode output file: {exc}", file=sys.stderr)
        return 65
    if evidence_file_arg:
        try:
            changed_file_paths = changed_file_paths_from_evidence(
                Path(evidence_file_arg).read_text(encoding="utf-8")
            )
        except OSError:
            changed_file_paths = []

    for value in iter_json_objects(output_text):
        control = valid_control(
            value,
            expected_head_sha=expected_head_sha,
            expected_run_id=expected_run_id,
            expected_run_attempt=expected_run_attempt,
            changed_file_paths=changed_file_paths,
        )
        if control is None:
            continue

        normalized_json = json.dumps(control, separators=(",", ":"), ensure_ascii=False)
        output_file.write_text(
            "\n".join(
                [
                    (
                        "<!-- opencode-review-gate "
                        f"head_sha={expected_head_sha} "
                        f"run_id={expected_run_id} "
                        f"run_attempt={expected_run_attempt} -->"
                    ),
                    "",
                    "<!-- opencode-review-control-v1",
                    normalized_json,
                    "-->",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return 0

    print("NO_CONCLUSION", file=sys.stderr)
    return 4


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
