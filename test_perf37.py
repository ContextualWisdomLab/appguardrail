import time
from appguardrail_core.controlplane import _drift_fp

def _drift_fp_orig(finding):
    return f"{finding.get('rule_id')}|{finding.get('file')}|{str(finding.get('message', ''))[:80]}"

def test_perf():
    f = {"rule_id": "rule_1", "file": "file_1.py", "message": "This is a long message that might need truncation " * 10}
    start = time.time()
    for _ in range(1000000):
        _drift_fp_orig(f)
    print(f"Orig: {time.time() - start:.4f}s")

test_perf()
