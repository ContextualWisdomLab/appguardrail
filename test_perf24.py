import time

def build_rule_metadata_orig(references):
    owasp_list, cwe_list = [], []
    for ref in references:
        if ref.startswith("OWASP "):
            owasp_list.append(ref)
        if ref.startswith("CWE-"):
            cwe_list.append(ref)
    return owasp_list, cwe_list

def build_rule_metadata_fast(references):
    owasp_list = [ref for ref in references if ref.startswith("OWASP ")]
    cwe_list = [ref for ref in references if ref.startswith("CWE-")]
    return owasp_list, cwe_list

def test_perf():
    references = ["OWASP 1", "CWE-2", "SOMETHING", "OWASP 3", "CWE-4"] * 10
    start = time.time()
    for _ in range(100000):
        build_rule_metadata_orig(references)
    print(f"Orig (single loop): {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(100000):
        build_rule_metadata_fast(references)
    print(f"Fast (generator): {time.time() - start:.4f}s")

test_perf()
