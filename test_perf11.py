import time
from typing import Mapping
_SENSITIVE_HEADERS = frozenset({"authorization", "proxy-authorization"})

def orig(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, value in headers.items()
        if name.lower() not in _SENSITIVE_HEADERS
    }

def fast(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, value in headers.items()
        if name.lower() not in {"authorization", "proxy-authorization"}
    }

def test_perf():
    headers = {"Content-Type": "application/json", "Authorization": "Bearer x", "Accept": "*/*", "Host": "example.com", "User-Agent": "test"}
    start = time.time()
    for _ in range(1000000):
        orig(headers)
    print(f"Orig: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(1000000):
        fast(headers)
    print(f"Fast: {time.time() - start:.4f}s")

test_perf()
