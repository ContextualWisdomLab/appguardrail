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
5. the function does not establish a small numeric `input.length` upper bound before the sink;
6. the search is function-bounded and character-bounded.

The file-level prefilter requires `[\s\S]*?` and `.match`, which avoids evaluating the multiline signature on unrelated source files.

## Source-authoritative evidence

`tests/test_javascript_lazy_xml_redos_rules.py` pins both sides of the reviewed ScopeWeave source change and exercises the production `_scan_file` entrypoint. The corpus includes:

- the vulnerable `<Task>[\s\S]*?<\/Task>` block collector;
- the reviewed linear `indexOf` / `slice` scanner as the primary negative oracle;
- a small explicitly length-bounded parser negative;
- a non-XML lazy-regex negative.

The detector therefore proves the observed source contract rather than treating a cancelled security workflow label as evidence of a vulnerability.

## Remediation boundary

Preferred remediation is a deterministic linear parser or delimiter scanner that advances monotonically after each complete block and stops once an opening delimiter has no closing delimiter. If a regular expression is retained, the application must impose a verified small input bound before matching and must separately establish the expression's worst-case complexity.

MITRE CWE-1333 defines inefficient regular-expression complexity as a weakness that can cause CPU resource exhaustion and explicitly recommends avoiding backtracking regular expressions on untrusted input or bounding input length. ECMAScript specifies RegExp matching using match states and backtracking semantics; the product must therefore not assume that a lazy quantifier implies linear execution.

## Declared limitations

This detector does not claim coverage for:

- nested or overlapping quantified expressions that do not use `[\s\S]*?`;
- regular expressions created through `RegExp(...)` strings;
- helper-mediated or cross-function dataflow;
- parsers whose input is bounded through a wrapper rather than the detected function;
- non-JavaScript regex engines;
- regular expressions whose complexity requires semantic or automata analysis.

Those cases require separate source-derived signatures or a structural/dataflow regex-complexity engine.

## APA 7 references

ECMA International. (2026). *ECMAScript 2026 language specification*. https://tc39.es/ecma262/2026/

MITRE Corporation. (2026). *CWE-1333: Inefficient regular expression complexity* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/1333.html

MITRE Corporation. (2026). *CWE-400: Uncontrolled resource consumption* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/400.html
