#!/usr/bin/env python3
"""Normalize OpenCode review output into the strict approval-gate contract."""

import json
import sys
from pathlib import Path
from typing import Any


def _validate_metadata(
    value: dict[str, Any],
    expected_head_sha: str,
    expected_run_id: str,
    expected_run_attempt: str,
) -> bool:
    if value.get("head_sha") != expected_head_sha:
        return False
    if value.get("run_id") != expected_run_id:
        return False
    if value.get("run_attempt") != expected_run_attempt:
        return False
    return True


def _validate_result_and_reason(value: dict[str, Any]) -> bool:
    result = value.get("result")
    if result not in {"APPROVE", "REQUEST_CHANGES"}:
        return False
    if not isinstance(value.get("reason"), str) or not value["reason"].strip():
        return False
    if not isinstance(value.get("summary"), str) or not value["summary"].strip():
        return False
    return True


def _validate_findings(value: dict[str, Any]) -> bool:
    result = value.get("result")
    findings = value.get("findings")
    if not isinstance(findings, list):
        return False
    if result == "APPROVE" and findings:
        return False
    if result == "REQUEST_CHANGES" and not findings:
        return False

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
            return False
        if not isinstance(finding.get("line"), int) or finding["line"] <= 0:
            return False
        for field in required_finding_fields:
            if not isinstance(finding.get(field), str) or not finding[field].strip():
                return False
    return True


def valid_control(
    value: Any,
    *,
    expected_head_sha: str,
    expected_run_id: str,
    expected_run_attempt: str,
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None

    if not _validate_metadata(
        value,
        expected_head_sha,
        expected_run_id,
        expected_run_attempt,
    ):
        return None

    if not _validate_result_and_reason(value):
        return None

    if not _validate_findings(value):
        return None

    return {
        "head_sha": value["head_sha"],
        "run_id": value["run_id"],
        "run_attempt": value["run_attempt"],
        "result": value["result"],
        "reason": value["reason"],
        "summary": value["summary"],
        "findings": value["findings"],
    }


def iter_json_objects(text: str) -> list[Any]:
    decoder = json.JSONDecoder()
    values: list[Any] = []
    index = 0
    while index < len(text):
        if text[index] != "{":
            index += 1
            continue
        try:
            value, end = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            index += 1
            continue
        values.append(value)
        index = end

    return values


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print(
            "usage: opencode_review_normalize_output.py "
            "<expected_head_sha> <expected_run_id> <expected_run_attempt> <output_file>",
            file=sys.stderr,
        )
        return 64

    expected_head_sha, expected_run_id, expected_run_attempt, output_file_arg = argv[1:]
    output_file = Path(output_file_arg)
    project_root = Path.cwd().resolve()

    if not output_file.resolve().is_relative_to(project_root):
        print(f"error: output file path {output_file_arg!r} is outside the project root", file=sys.stderr)
        return 65

    try:
        output_text = output_file.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"cannot read OpenCode output file: {exc}", file=sys.stderr)
        return 65

    for value in iter_json_objects(output_text):
        control = valid_control(
            value,
            expected_head_sha=expected_head_sha,
            expected_run_id=expected_run_id,
            expected_run_attempt=expected_run_attempt,
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
