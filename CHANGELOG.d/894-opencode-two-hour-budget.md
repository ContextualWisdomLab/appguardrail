### Changed

- Replaced the repository-authored 170-minute OpenCode job deadline with non-cancelling single-flight execution. Hourly runs remain serialized, but a later schedule tick no longer terminates an active reasoning or tool-execution slice solely because elapsed time crossed a local workflow budget; user, provider, platform, and administrative termination remain separate stop conditions.
