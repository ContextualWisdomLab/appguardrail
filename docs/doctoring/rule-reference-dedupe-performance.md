# Rule-reference deduplication performance boundary

## Decision

`extract_public_references()` and `_merge_references()` execute for normalized
findings and must preserve first-seen order while removing duplicates. The
implementation replaces generator expressions passed to `dict.fromkeys()` with:

- a bounded list comprehension for normalized regex matches; and
- `filter(None, itertools.chain.from_iterable(...))` for reference-group merging.

This is a bounded constant-factor optimization. It does not change the public
metadata schema, accepted bracketed reference grammar, category overrides,
OWASP/CWE classification, or remediation copy. It does not claim a material
end-to-end scan speedup without a representative repository benchmark.

## Executable contract

`tests/test_rules_allocation_contract.py` inspects the compiled code objects and
requires both hot paths to contain no nested `<genexpr>` frame. Existing
`tests/test_rules_core.py` continues to prove first-seen ordering, duplicate
suppression, bracketed-only extraction, CVE preservation, and exclusive
OWASP/CWE classification.

## Local microbenchmark evidence

The following measurements used CPython 3.13.5 on Linux x86_64, five repeats,
and the median elapsed time. Small cases used 20,000 calls per repeat; the
200-value cases used 2,000 calls per repeat. The baseline is PR #976's tested
bracket fast path with generator-based deduplication. Lower is better.

| Case | Baseline median | Candidate median | Change |
| --- | ---: | ---: | ---: |
| Extract 1 bracketed reference | 0.018451 s | 0.016543 s | -10.3% |
| Extract 6 bracketed references | 0.057949 s | 0.055650 s | -4.0% |
| Extract 12 bracketed references | 0.106003 s | 0.110610 s | +4.3% |
| Extract 200 bracketed references | 0.147711 s | 0.137972 s | -6.6% |
| Merge 6 reference values | 0.014602 s | 0.012779 s | -12.5% |
| Merge 12 reference values | 0.023947 s | 0.018760 s | -21.7% |
| Merge 200 reference values | 0.029639 s | 0.023031 s | -22.3% |

The 12-reference extraction case regressed slightly in this microbenchmark, so
the change is not represented as universally faster. Typical AppGuardrail rule
copy carries zero to a few bracketed IDs, while category merging combines only
a few public/default references. Messages without `[` remain governed by PR
#976's substring fast path and receive no meaningful benefit from this change.
These measurements are local microbenchmarks, not production latency or
throughput evidence.

## Rollback

Revert the allocation change if representative scan profiling shows a regression
or the bounded temporary list becomes material. Preserve the bracket fast path,
first-seen order, exact reference semantics, and the allocation contract unless
a separately reviewed implementation supplies equivalent evidence.

## References

Python Software Foundation. (2026). *6. Expressions—Python 3.14.7
documentation*. https://docs.python.org/3.14/reference/expressions.html

Python Software Foundation. (2026). *Built-in types—Python 3.14.7
documentation*. https://docs.python.org/3.14/library/stdtypes.html
