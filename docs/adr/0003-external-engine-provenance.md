# ADR-0003: Preserve external scanner provenance

**Status:** Accepted  
**Date:** 2026-08-09

Optional engines such as Trivy, Bandit, Ruff, Semgrep, and ZAP remain distinct evidence producers. AppGuardrail normalizes their findings for common reporting/gating without claiming those analyses were produced by its lightweight built-in matcher. Tool unavailable/failed/clean/finding states remain distinguishable and engine/rule/version/source provenance survives serialization.

## References

OASIS Open. (2020). *Static Analysis Results Interchange Format (SARIF) Version 2.1.0*. OASIS. https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html