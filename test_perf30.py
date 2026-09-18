import time
import re

REFERENCE_RE = re.compile(
    r"\b((?:OWASP(?: Top 10)?:?\s*(?:A\d+(?::\d+)?\b)?)|(?:CWE-\d+)|(?:CVE-\d{4}-\d+))\b",
    re.IGNORECASE,
)

def extract_public_references(message: str) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            " ".join(match.group(1).split())
            for match in REFERENCE_RE.finditer(message or "")
        )
    )

def extract_public_references_fast(message: str) -> tuple[str, ...]:
    if not message:
        return ()
    # Fast path string containment before regex
    lowered = message.lower()
    if "owasp" not in lowered and "cwe-" not in lowered and "cve-" not in lowered:
        return ()
    return tuple(
        dict.fromkeys(
            " ".join(match.group(1).split())
            for match in REFERENCE_RE.finditer(message)
        )
    )

def test_perf():
    message = "Just some normal message without any references." * 10
    start = time.time()
    for _ in range(100000):
        extract_public_references(message)
    print(f"Orig (no match): {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(100000):
        extract_public_references_fast(message)
    print(f"Fast (no match): {time.time() - start:.4f}s")

    message = "This message has CWE-79 and OWASP in it." * 10
    start = time.time()
    for _ in range(100000):
        extract_public_references(message)
    print(f"Orig (match): {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(100000):
        extract_public_references_fast(message)
    print(f"Fast (match): {time.time() - start:.4f}s")

test_perf()
