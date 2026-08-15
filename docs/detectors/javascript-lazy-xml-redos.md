# JavaScript lazy XML block ReDoS detector

**Status:** Source-derived detector slice  
**Rule ID:** `javascript-xml-lazy-dotall-block-redos`  
**Primary weakness classes:** CWE-1333, CWE-400  
**Source change:** `ContextualWisdomLab/scopeweave` PR #386; vulnerable base head `a756b7e3cf486cba0930c1a482c6a30e0df958f5` / blob `7e44932baf55854d18f7ef9da0937d14f982b9ed`; reviewed fixed head `bd9a51584f1cf37f4f4446022a90775a20152edf` / blob `9016cfbf157b812a738bf8f7f9063f43b4af2737`

## Buyer-visible protection

The collected ScopeWeave source parsed imported Microsoft Project XML with global JavaScript regular expressions such as `/<Task>[\s\S]*?<\/Task>/g`. On malformed input containing many opening tags without the expected closing delimiter, the backtracking engine can repeatedly rescan overlapping suffixes. That creates an availability boundary: a small crafted import can consume disproportionately large CPU time in the browser process.

The packaged rule reports this bounded source shape before release. It is intentionally narrower than a general regular-expression complexity analyzer.

## Detection contract

The detector requires all of the following evidence in one JavaScript or TypeScript function:

1. the first function parameter is the direct receiver of `.match(...)` or `.matchAll(...)`;
2. the regular expression starts with an XML-like opening tag and ends with the same closing tag;
3. the block body uses lazy dot-all emulation `[\s\S]*?`;
4. the expression is global (`g`), so the engine is asked to continue searching the same untrusted input;
5. the function does not establish an immediately terminating `if (input.length > N) throw ...` or `if (input.length > N) return ...` guard before the sink, where the detector recognizes only one- through four-digit caps (`N <= 9999`) as a deliberately small local bound; and
6. the search is function-bounded and protected by the file-level prefilter described below.

A length comparison that only logs, records telemetry, or otherwise continues to the regex sink is not a bound. Six-digit and larger thresholds are intentionally not treated as protective evidence; applications needing a larger limit should replace the backtracking block collector or establish safety through a separately reviewed structural detector.

The file-level prefilter requires `[\s\S]*?` and `.match`, which avoids evaluating the multiline signature on unrelated source files. The shared rule is also consumed by Semgrep: its function-bound scans deliberately avoid large fixed-width `{0,N}` repetitions, because the prior 2,000/6,000/8,000-character windows exceeded Semgrep's regex compilation capacity for this expression. Regression coverage rejects reintroduction of those large bounded scans, while the required Semgrep/Strix gate supplies the executable compatibility oracle.

## Source-authoritative evidence

`tests/test_javascript_lazy_xml_redos_rules.py` pins both immutable ScopeWeave `cloud-sync.js` blob identities and replays the exact `parseMsProjectXml` function sections from those revisions rather than independently authored approximations. The committed section fixtures correspond to vulnerable lines 741–780 and fixed lines 741–809 and carry independent SHA-256 digests so fixture drift fails deterministically. The tests exercise the production `_scan_file` entrypoint. The corpus includes:

- the exact vulnerable `<Task>[\s\S]*?<\/Task>` block collector from the pinned vulnerable blob;
- the exact reviewed linear `indexOf` / `slice` implementation from the pinned fixed blob as the primary negative oracle;
- a small explicitly terminating length-bounded parser negative;
- six-digit, post-sink, and non-terminating length-check positives; and
- a non-XML lazy-regex negative.

The upstream Git blob SHAs remain the authoritative complete-file identities; the vendored fixtures intentionally contain only the detector-relevant function sections, avoiding unrelated application code while preserving byte-exact detector evidence. The detector therefore proves the observed source contract rather than treating a cancelled security workflow label as evidence of a vulnerability.

## Remediation boundary

Preferred remediation is a deterministic linear parser or delimiter scanner that advances monotonically after each complete block and stops once an opening delimiter has no closing delimiter. If a regular expression is retained, the application must impose a verified small input bound before matching, terminate the oversized-input path before the sink, and separately establish the expression's worst-case complexity.

MITRE CWE-1333 defines inefficient regular-expression complexity as a weakness that can cause CPU resource exhaustion and explicitly recommends avoiding backtracking regular expressions on untrusted input or bounding input length. ECMAScript specifies RegExp matching using match states and backtracking semantics; the product must therefore not assume that a lazy quantifier implies linear execution.

## Declared limitations

This detector currently recognizes only ordinary function declarations (`function name(...)`) and `export function` declarations. It does not detect the same source shape inside `async function`, `export default function`, arrow functions, class/object methods, or function declarations with TypeScript return-type annotations.

It also does not claim coverage for:

- nested or overlapping quantified expressions that do not use `[\s\S]*?`;
- regular expressions created through `RegExp(...)` strings;
- helper-mediated or cross-function dataflow;
- parsers whose input is bounded through a wrapper rather than the detected function;
- non-JavaScript regex engines; or
- regular expressions whose complexity requires semantic or automata analysis.

Those cases require separate source-derived signatures or a structural/dataflow regex-complexity engine.

## APA 7 references

ECMA International. (2026). *ECMAScript 2026 language specification*. https://tc39.es/ecma262/2026/

MITRE Corporation. (2026). *CWE-1333: Inefficient regular expression complexity* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/1333.html

MITRE Corporation. (2026). *CWE-400: Uncontrolled resource consumption* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/400.html

Semgrep, Inc. (2026). *Static analysis and rule-writing glossary*. https://semgrep.dev/docs/writing-rules/glossary
