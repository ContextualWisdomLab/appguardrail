"""Compare two findings snapshots: fixed / new / persisting.

Buyers and auditors ask one question about a security review: "is it getting
better?" This renders the answer from two `scan --findings-json` snapshots —
what was fixed, what is new, and what persists — as markdown evidence.

Fingerprint matches the control plane's drift key (rule + file + message head)
so a finding that merely moves lines still counts as persisting, not fixed+new.
Stdlib only. Usage: ``python -m appguardrail_core.diffreport old.json new.json``.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Iterable

from .findings import is_deploy_blocking, normalize_findings


def _fp(finding: dict[str, Any]) -> str:
    """Line-independent fingerprint (same shape as the control plane drift key)."""
    return f"{finding['rule_id']}|{finding['file']}|{finding['message'][:80]}"


def diff_findings(
    old: Iterable[dict[str, Any]], new: Iterable[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    """Split into fixed (old only), new (new only), persisting (both)."""
    old_map = {_fp(f): f for f in normalize_findings(old)}
    new_map = {_fp(f): f for f in normalize_findings(new)}
    return {
        "fixed": [f for k, f in old_map.items() if k not in new_map],
        "new": [f for k, f in new_map.items() if k not in old_map],
        "persisting": [f for k, f in new_map.items() if k in old_map],
    }


def _section(title: str, items: list[dict[str, Any]], cap: int = 30) -> list[str]:
    lines = [f"### {title} ({len(items)})", ""]
    if not items:
        lines.append("_none_")
        lines.append("")
        return lines
    lines.append("| Severity | Rule | Location |")
    lines.append("| --- | --- | --- |")
    for f in items[:cap]:
        loc = f"{f['file']}:{f['line']}".replace("|", "\\|")
        lines.append(f"| {f['severity']} | `{f['rule_id']}` | `{loc}` |")
    if len(items) > cap:
        lines.append("")
        lines.append(f"…and {len(items) - cap} more.")
    lines.append("")
    return lines


def render_diff_report(
    old: Iterable[dict[str, Any]], new: Iterable[dict[str, Any]]
) -> str:
    """Markdown progress report between two findings snapshots."""
    d = diff_findings(old, new)
    fixed_blocking = sum(1 for f in d["fixed"] if is_deploy_blocking(f))
    new_blocking = sum(1 for f in d["new"] if is_deploy_blocking(f))
    persist_blocking = sum(1 for f in d["persisting"] if is_deploy_blocking(f))

    if new_blocking:
        verdict = f"⚠️ 회귀: 새 deploy-blocking {new_blocking}건이 생겼습니다."
    elif fixed_blocking and not persist_blocking:
        verdict = f"✅ 개선: deploy-blocking {fixed_blocking}건이 모두 해결됐고 새 blocking은 없습니다."
    elif fixed_blocking:
        verdict = (
            f"📈 진행 중: deploy-blocking {fixed_blocking}건 해결, {persist_blocking}건 잔존, 새 blocking 없음."
        )
    else:
        verdict = f"➡️ 변화 없음: deploy-blocking {persist_blocking}건 잔존, 새 blocking 없음."

    md = ["# 🛡️ AppGuardrail 진행 리포트 (diff)", "", verdict, ""]
    md.append(
        f"- 해결됨 **{len(d['fixed'])}** (blocking {fixed_blocking}) · "
        f"신규 **{len(d['new'])}** (blocking {new_blocking}) · "
        f"잔존 **{len(d['persisting'])}** (blocking {persist_blocking})"
    )
    md.append("")
    md.extend(_section("🆕 신규 (New)", d["new"]))
    md.extend(_section("✅ 해결됨 (Fixed)", d["fixed"]))
    md.extend(_section("⏳ 잔존 (Persisting)", d["persisting"]))
    return "\n".join(md)


def load_findings(path: str) -> list[dict[str, Any]]:
    """Accept the findings.v1 envelope, a bare array, or any {findings: []}."""
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    return payload.get("findings", payload) if isinstance(payload, dict) else payload


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(
            "usage: python -m appguardrail_core.diffreport <old-findings.json> <new-findings.json>",
            file=sys.stderr,
        )
        return 2
    print(render_diff_report(load_findings(argv[0]), load_findings(argv[1])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
