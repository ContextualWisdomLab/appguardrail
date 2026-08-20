# Rule-reference deduplication performance boundary

## Decision

`extract_public_references()` and `_merge_references()` execute for normalized
findings and must preserve first-seen order while removing duplicates. The
implementation uses insertion-ordered dictionaries and explicit loops rather
than generator expressions passed to `dict.fromkeys()`.

This is a bounded constant-factor optimization. It does not change the public
metadata schema, accepted bracketed reference grammar, category overrides,
OWASP/CWE classification, or remediation copy. It also does not claim a
material end-to-end scan speedup without a representative repository benchmark.

## Executable contract

`tests/test_rules_allocation_contract.py` inspects the compiled code objects and
requires both hot paths to contain no nested `<genexpr>` frame. Existing
`tests/test_rules_core.py` continues to prove first-seen ordering, duplicate
suppression, bracketed-only extraction, CVE preservation, and exclusive
OWASP/CWE classification.

## Local microbenchmark evidence

The following measurements used CPython 3.13.5 on Linux x86_64, seven repeats,
100,000 calls per repeat, and the median elapsed time. The baseline is PR #976's
already-tested bracket fast path; only generator removal differs.

| Case | Baseline median | Explicit-loop median | Change |
| --- | ---: | ---: | ---: |
| One bracketed reference | 0.1088 s | 0.0828 s | -23.9% |
| Twelve bracketed references | 0.5292 s | 0.4837 s | -8.6% |
| Merge six reference values | 0.0468 s | 0.0310 s | -33.8% |
| Merge 200 reference values | 0.6562 s | 0.6388 s | -2.7% |

Messages without `[` remain governed by PR #976's earlier substring fast path;
the explicit-loop change provides no meaningful improvement on that early-return
case. Results are microbenchmarks, not production latency or throughput claims.

## Rollback

Revert the explicit loops only if profiling on representative scan workloads
shows a regression or maintainability cost. Preserve the bracket fast path,
first-seen order, exact reference semantics, and allocation regression contract
unless a separately reviewed implementation supplies equivalent evidence.

## References

Python Software Foundation. (2026). *6. Expressions—Python 3.14.7
documentation*. https://docs.python.org/3.14/reference/expressions.html

Python Software Foundation. (2026). *Built-in types—Python 3.14.7
documentation*. https://docs.python.org/3.14/library/stdtypes.html
