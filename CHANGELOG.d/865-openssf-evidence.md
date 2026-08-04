### Added

- Added fixed-origin current and legacy OpenSSF Best Practices evidence collection with explicit `in_progress`, `passing`, `silver`, `gold`, `unavailable`, `malformed`, and permission-limited states.
- Added normalized evidence metadata and an offline JSON ingestion path for reproducible buyer-diligence artifacts.
- Added a dedicated OpenSSF Best Practices section to buyer-diligence reports, preserving tier, evidence URL, and verification timestamp without treating unavailable evidence as proof of non-registration.
- Buyer-diligence rendering now fails closed when externally supplied verification status, badge tier, or evidence URL metadata is inconsistent, preventing malformed records from being displayed as affirmative badge claims.
