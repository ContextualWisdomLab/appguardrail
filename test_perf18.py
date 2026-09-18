import time
import appguardrail_core.controlplane

def test_perf():
    blocking_findings = [{"id": f"id_{i}", "file": f"file_{i}", "line": i, "severity": "HIGH"} for i in range(1000)]
    prev_fps = [f"prev_fp_{i}" for i in range(1000)]

    start = time.time()
    for _ in range(100):
        new_findings = [f for f in blocking_findings if appguardrail_core.controlplane._drift_fp(f) not in prev_fps]
    print(f"Original: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(100):
        prev_fps_set = set(prev_fps)
        new_findings = [f for f in blocking_findings if appguardrail_core.controlplane._drift_fp(f) not in prev_fps_set]
    print(f"Fast: {time.time() - start:.4f}s")

test_perf()
