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
    if not message or ("owasp" not in message.lower() and "cwe-" not in message.lower() and "cve-" not in message.lower()):
        return ()
    return tuple(
        dict.fromkeys(
            " ".join(match.group(1).split())
            for match in REFERENCE_RE.finditer(message)
        )
    )

def extract_public_references_fast2(message: str) -> tuple[str, ...]:
    if not message:
        return ()
    # Avoid allocating lower() for the whole string if possible, maybe fast pre-check?
    # Actually wait, regex does finditer and allocation anyway.
    # Just skip if no matches.
    if not REFERENCE_RE.search(message):
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
    print(f"Orig: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(100000):
        extract_public_references_fast(message)
    print(f"Fast1: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(100000):
        extract_public_references_fast2(message)
    print(f"Fast2: {time.time() - start:.4f}s")

test_perf()
