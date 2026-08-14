# JavaScript CSV formula leading-whitespace detector

**Status:** Source-derived detector slice  
**Rule ID:** `javascript-csv-formula-leading-whitespace-bypass`  
**Primary weakness class:** CWE-1236  
**Source change:** `ContextualWisdomLab/scopeweave` PR #386; vulnerable base head `a756b7e3cf486cba0930c1a482c6a30e0df958f5` / `server/app.mjs` blob `926d528d17b7ae39ab89001657a21f7ef30af743`; reviewed fixed head `bd9a51584f1cf37f4f4446022a90775a20152edf` / blob `13d95e5dfa0719451a5b4a6d952467994172b79a`

## Buyer-visible protection

The collected ScopeWeave audit exporter attempted to neutralize spreadsheet formulas only when the first raw character of a field was `=`, `+`, `-`, `@`, or `|`. A value with leading whitespace followed by a formula-sensitive prefix bypassed that guard and was emitted into a `text/csv` response. The detector reports this exact narrow neutralization defect before a spreadsheet-facing export reaches production.

## Detection contract

The detector requires all of the following evidence in JavaScript or TypeScript source:

1. a regex guard checks a local value with the exact raw-start character class `^[=+\-@|]`;
2. the guarded value is prefixed as text after the test;
3. a `text/csv` sink occurs within a bounded 5,000-character window;
4. the file also contains `.join(',')`, consistent with CSV serialization.

The detector intentionally does not flag exporters that have no recognizable neutralizer. Detecting a missing source-to-CSV neutralization path requires dataflow analysis and is a separate obligation. The fixed source uses `^\s*[=+\-@|]`, so this source-derived rule no longer matches it.

## Source-authoritative evidence corpus

`tests/test_javascript_csv_formula_rules.py` pins the exact vulnerable and reviewed fixed ScopeWeave revisions and blobs. It preserves:

- the vulnerable audit CSV exporter;
- the reviewed whitespace-aware negative oracle;
- the same regex guard outside a CSV sink as a negative;
- a CSV exporter with no recognizable guard as an explicit not-claimed case;
- production `_scan_file` execution with HIGH severity and CWE-1236 normalization.

## Remediation boundary

CWE-1236 identifies CSV/formula injection when user-controlled content is written into spreadsheet-compatible files without effective neutralization of formula elements. OWASP similarly notes that formula-sensitive prefixes can be interpreted by spreadsheet applications and that delimiter/quoting behavior makes mitigation context-dependent. The source-derived repair here is intentionally limited to the observed leading-whitespace bypass; it is not presented as a universal spreadsheet neutralization strategy.

For a production exporter, apply one centrally reviewed field-encoding policy to every untrusted cell, validate the intended spreadsheet consumers, and regression-test delimiter, quote, line-break, formula-prefix, full-width and locale-sensitive cases appropriate to those consumers. Do not rely on this narrow detector as proof that an arbitrary CSV exporter is universally safe.

## Declared limitations

This detector does not claim coverage for:

- exporters with no formula guard at all;
- guards implemented through helper functions or dataflow across files;
- tabs, carriage returns, line feeds, full-width characters, delimiters, or quote-based cell splitting unless represented by the exact observed source shape;
- non-JavaScript exporters;
- spreadsheet-specific re-save behavior;
- alternate safe encoding strategies that do not resemble the reviewed ScopeWeave fix.

Those cases require separate source-derived detectors or a structural/dataflow CSV-export analysis engine.

## APA 7 references

MITRE Corporation. (2026). *CWE-1236: Improper neutralization of formula elements in a CSV file* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/1236.html

OWASP Foundation. (n.d.). *CSV injection*. https://owasp.org/www-community/attacks/CSV_Injection

OWASP Foundation. (n.d.). *Testing for CSV injection (WSTG-INPV-21)*. https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/21-Testing_for_CSV_Injection
