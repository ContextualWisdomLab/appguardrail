import time
from appguardrail_core.controlplane import _drift_fp

def compute_drift_fp_list(blocking_findings, prev_fps):
    return [f for f in blocking_findings if _drift_fp(f) not in prev_fps]

def compute_drift_fp_set(blocking_findings, prev_fps_set):
    return [f for f in blocking_findings if _drift_fp(f) not in prev_fps_set]

def test_perf():
    # Make a large set of previous fps
    prev_fps = [f"prev_fp_{i}" for i in range(1000)]
    prev_fps_set = set(prev_fps)

    # Make findings
    blocking_findings = [{"id": f"id_{i}", "file": f"file_{i}", "line": i, "severity": "HIGH"} for i in range(1000)]

    start = time.time()
    for _ in range(100):
        compute_drift_fp_list(blocking_findings, prev_fps)
    print(f"List: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(100):
        compute_drift_fp_set(blocking_findings, prev_fps_set)
    print(f"Set: {time.time() - start:.4f}s")

test_perf()
