import time
from appguardrail_core.findings import _SEVERITY_ORDER

DEPLOY_BLOCKING_SEVERITIES = {"CRITICAL", "HIGH"}
NON_BLOCKING_CONTEXTS = {"test", "doc", "example", "scanner-fixture"}

def is_deploy_blocking_orig(finding, blocking_severities=None):
    severities = blocking_severities or DEPLOY_BLOCKING_SEVERITIES

    sev = finding.get("severity")
    if type(sev) is not str or sev not in _SEVERITY_ORDER:
        try:
            sev = str(sev or "INFO").upper()
        except Exception:
            sev = "INFO"

    ctx = finding.get("context")
    if type(ctx) is not str or not ctx:
        try:
            ctx = str(ctx or "app-code")
        except Exception:
            ctx = "app-code"

    return sev in severities and ctx not in NON_BLOCKING_CONTEXTS

def is_deploy_blocking_fast(finding, blocking_severities=None):
    severities = blocking_severities or DEPLOY_BLOCKING_SEVERITIES

    sev = finding.get("severity")
    if not isinstance(sev, str) or sev not in _SEVERITY_ORDER:
        sev = str(sev or "INFO").upper() if sev else "INFO"

    ctx = finding.get("context")
    if not isinstance(ctx, str) or not ctx:
        ctx = str(ctx or "app-code") if ctx else "app-code"

    return sev in severities and ctx not in NON_BLOCKING_CONTEXTS

def test_perf():
    f = {"severity": "HIGH", "context": "app-code"}
    start = time.time()
    for _ in range(1000000):
        is_deploy_blocking_orig(f)
    print(f"Orig: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(1000000):
        is_deploy_blocking_fast(f)
    print(f"Fast: {time.time() - start:.4f}s")

test_perf()
