### Changed

- Replaced the hourly commercial-readiness agent handoff with an immutable, default-branch-only OpenCode GitHub Action using `NVIDIA_NIM_API_KEY` through OpenCode's built-in NVIDIA provider.
- Added a fail-closed canonical gap specification so mutable GitHub issue text is treated as untrusted data rather than agent instructions.
- Extended the commercial builder window to 120 minutes while preserving PR-first single-flight execution and independent protected review.
