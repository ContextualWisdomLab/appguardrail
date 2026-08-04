### Added

- Added fixed-origin current and historical OpenSSF Best Practices evidence collection with explicit `in_progress`, `passing`, `silver`, `gold`, `unavailable`, `malformed`, and permission-limited states.
- Added normalized evidence metadata and a bounded offline JSON ingestion path for reproducible buyer-diligence artifacts.
- Added a dedicated OpenSSF Best Practices section to buyer-diligence reports, preserving tier, evidence URL, verification timestamp, source attribution, and the current date-dependent content-license policy without treating unavailable evidence as proof of non-registration.
- Evidence collection now requires the returned project `repo_url` or `homepage_url` to match the queried URL, requires canonical UTC timestamps and JSON media types, rejects recursively malformed or oversized input, closes HTTP error streams, and returns concise non-zero CLI errors for invalid repository or timestamp input.
- Buyer-diligence rendering now fails closed when externally supplied verification status, badge tier, project ID, or evidence URL metadata is inconsistent, preventing malformed records from being displayed as affirmative badge claims.
- Corrected package metadata and documentation to the tested Python 3.11 minimum.
