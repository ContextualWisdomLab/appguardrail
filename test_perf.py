import time
from typing import Iterable, Any

SEVERITIES = ("CRITICAL", "HIGH", "WARNING", "INFO")


def severity_counts_old(findings: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = str(finding.get("severity") or "INFO").upper()
        counts[severity if severity in counts else "INFO"] += 1
    return counts


def severity_counts_new(findings: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = finding.get("severity")
        if not severity:
            counts["INFO"] += 1
            continue

        severity = str(severity).upper()
        if severity in counts:
            counts[severity] += 1
        else:
            counts["INFO"] += 1
    return counts


def test():
    findings = (
        [{"severity": "CRITICAL"}] * 10000
        + [{"severity": "HIGH"}] * 10000
        + [{"severity": "WARNING"}] * 10000
        + [{"severity": "INFO"}] * 10000
        + [{"severity": None}] * 10000
        + [{"severity": "UNKNOWN"}] * 10000
    )

    start = time.perf_counter()
    for _ in range(100):
        severity_counts_old(findings)
    print(f"Old: {time.perf_counter() - start:.4f}s")

    start = time.perf_counter()
    for _ in range(100):
        severity_counts_new(findings)
    print(f"New: {time.perf_counter() - start:.4f}s")


if __name__ == "__main__":
    test()
