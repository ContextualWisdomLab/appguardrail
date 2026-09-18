import time
from appguardrail_core.rules import build_rule_metadata

def test_perf():
    start = time.time()
    for _ in range(100000):
        build_rule_metadata(
            "rule-1", "HIGH", "Message with OWASP A1 and CWE-79", category="unknown"
        )
    print(f"Orig: {time.time() - start:.4f}s")
test_perf()
