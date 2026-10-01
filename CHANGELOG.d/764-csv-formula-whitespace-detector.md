# ScopeWeave PR #386 event family — CSV formula leading-whitespace detector

## Added

- Added the HIGH-severity `javascript-csv-formula-leading-whitespace-bypass` rule for JavaScript/TypeScript CSV exporters whose formula-prefix guard checks only the first raw character and can be bypassed by leading whitespace.
- Added immutable vulnerable and fixed ScopeWeave source identities plus production-scanner replay and explicit negative boundaries for non-CSV use and missing-neutralizer dataflow that this rule does not claim to solve.
- Added CSV-context prefilters and a bounded `text/csv` sink window.

## Documentation

- Added source-derived remediation guidance, declared limitations, and APA 7 references to CWE-1236 and OWASP CSV Injection/WSTG guidance.
- Preserved the collected ScopeWeave PR #386 workflow-event provenance while grounding efficacy in the independently reviewed source change.
