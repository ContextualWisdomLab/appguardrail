# ScopeWeave PR #386 event family — JavaScript lazy XML block ReDoS detector

## Added

- Added the HIGH-severity `javascript-xml-lazy-dotall-block-redos` rule for unbounded JavaScript XML-like block collection with global lazy `[\s\S]*?` expressions.
- Added immutable vulnerable and fixed ScopeWeave source identities, production scanner replay, and negative cases for the reviewed linear scanner, bounded input, and non-XML lazy matching.
- Added a two-token prefilter and function/input binding so unrelated regexes are not classified as this source-derived weakness.

## Documentation

- Added the detector contract, linear-scan remediation boundary, declared limitations, and APA 7 references to ECMAScript 2026, CWE-1333, and CWE-400.
- Preserved the collected PR #386 security-event family as provenance while treating the underlying source change—not cancelled workflow status—as the efficacy oracle.
