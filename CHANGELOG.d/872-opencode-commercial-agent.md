### Changed

- Replaced the hourly Jules issue handoff with a bounded OpenCode commercial builder using `NVIDIA_NIM_API_KEY` through OpenCode's built-in NVIDIA provider.
- Generate the model-authoritative task from the reviewed default-branch registry, treat GitHub issue prose as untrusted, and fail closed on marker, title, identity, or credential mismatches.
- Preserve the independent review-agent credential and approval path while keeping the development agent PR-first, single-flight, test-first, and prohibited from merging or releasing its own work.
