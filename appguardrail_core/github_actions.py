"""GitHub Actions native output for AppGuardrail scans.

When a scan runs inside GitHub Actions (``GITHUB_ACTIONS=true``), findings should
show up where developers already look: inline on the PR diff (workflow
annotations) and in the run's job summary (``$GITHUB_STEP_SUMMARY``). This module
turns findings into those two GitHub-native surfaces. No extra workflow steps
needed — the existing monitor workflow gains inline annotations for free.

Stdlib only.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Iterable

from .findings import normalize_findings, severity_counts, is_deploy_blocking


def in_actions() -> bool:
    """True when running inside a GitHub Actions runner."""
    return os.environ.get("GITHUB_ACTIONS") == "true"


def _esc_data(text: str) -> str:
    # GitHub workflow-command message escaping.
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _esc_prop(text: str) -> str:
    # Property values additionally escape ',' and ':'.
    return _esc_data(text).replace(",", "%2C").replace(":", "%3A")


def annotation_lines(
    findings: Iterable[dict[str, Any]],
    is_blocking: Callable[[dict[str, Any]], bool] = is_deploy_blocking,
) -> list[str]:
    """One ``::error``/``::warning`` workflow command per finding.

    Deploy-blocking findings become errors (fail the check + red annotation);
    everything else is a warning so it still surfaces without failing.
    """
    lines = []
    for f in normalize_findings(findings):
        level = "error" if is_blocking(f) else "warning"
        title = _esc_prop(f"AppGuardrail: {f['rule_id']}")
        file_ = _esc_prop(str(f["file"]))
        message = _esc_data(f["message"].strip())
        lines.append(
            f"::{level} file={file_},line={f['line']},title={title}::{message}"
        )
    return lines


def step_summary_md(
    findings: Iterable[dict[str, Any]],
    files_scanned: int,
    is_blocking: Callable[[dict[str, Any]], bool] = is_deploy_blocking,
) -> str:
    """Compact GitHub-flavored markdown for the Actions job summary."""
    found = list(normalize_findings(findings))
    counts = severity_counts(found)
    blocking = [f for f in found if is_blocking(f)]

    md = ["## 🛡️ AppGuardrail scan", ""]
    if not found:
        md.append(f"No findings across {files_scanned} file(s). ✅")
        return "\n".join(md) + "\n"

    verdict = (
        f"**{len(blocking)} deploy-blocking** finding(s) ❌"
        if blocking
        else "No deploy-blocking findings ✅"
    )
    md.append(
        f"{verdict} — {len(found)} total across {files_scanned} file(s)."
    )
    md.append("")
    md.append("| Severity | Count |")
    md.append("| --- | ---: |")
    for sev in ("CRITICAL", "HIGH", "WARNING", "INFO"):
        if counts.get(sev):
            md.append(f"| {sev} | {counts[sev]} |")
    md.append("")
    # Top blocking findings first, capped so the summary stays readable.
    top = (blocking or found)[:20]
    md.append("| Severity | Rule | Location |")
    md.append("| --- | --- | --- |")
    for f in top:
        loc = f"{f['file']}:{f['line']}".replace("|", "\\|")
        rule = str(f["rule_id"]).replace("|", "\\|")
        md.append(f"| {f['severity']} | `{rule}` | `{loc}` |")
    shown = len(top)
    total_pool = len(blocking or found)
    if total_pool > shown:
        md.append("")
        md.append(f"…and {total_pool - shown} more.")
    return "\n".join(md) + "\n"


def emit(
    findings: Iterable[dict[str, Any]],
    files_scanned: int,
    is_blocking: Callable[[dict[str, Any]], bool] = is_deploy_blocking,
) -> None:
    """Print annotations to stdout and append a summary to GITHUB_STEP_SUMMARY."""
    found = list(normalize_findings(findings))
    for line in annotation_lines(found, is_blocking):
        print(line)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as fh:
                fh.write(step_summary_md(found, files_scanned, is_blocking))
        except OSError:
            # A broken/unwritable summary path must never fail the scan.
            pass


if __name__ == "__main__":  # pragma: no cover - self-check
    fs = [
        {"severity": "CRITICAL", "rule_id": "secret", "file": "a,b.ts", "line": 3,
         "message": "hardcoded key\nrotate it", "context": "app-code"},
        {"severity": "INFO", "rule_id": "note", "file": "README.md", "line": 1,
         "message": "fyi", "context": "doc"},
    ]
    lines = annotation_lines(fs)
    assert lines[0].startswith("::error "), lines[0]
    assert lines[1].startswith("::warning "), lines[1]
    assert "%2C" in lines[0]  # comma in filename escaped
    assert "%0A" in lines[0]  # newline in message escaped
    md = step_summary_md(fs, 5)
    assert "deploy-blocking" in md and "CRITICAL" in md
    assert step_summary_md([], 5).endswith("✅\n")
    print("github_actions self-check OK")
