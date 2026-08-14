# Changed

- Route the embedded control-plane runtime through the version-two canonical SQLite schema migration before serving or returning a connection.
- Read and write `tenant_organizations`, `security_scans`, and `access_keys` directly instead of bootstrapping the legacy `orgs`, `scans`, and `keys` tables.
- Fail closed on ambiguous schema migration and close a newly opened runtime connection before propagating the startup error.

This is a bounded runtime-integration slice of issue #871; it does not claim completion of retention-policy mutation, purge execution, buyer-evidence export, or remaining column-name normalization.