### Changed

- Treat missing, malformed, or non-canonical finding severities as `CRITICAL` across normalization, counting, deploy-gate evaluation, and sorting so ambiguous security evidence cannot silently become informational or non-blocking.
