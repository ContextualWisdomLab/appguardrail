### Added

- Added a reviewed hourly commercial-readiness loop that remains pull-request-first, dispatches at most one buyer-visible product gap through ordinary IssueOps, and preserves all existing review, check, and branch-protection gates.
- Added fail-closed recovery for interrupted issue-to-Jules handoffs so a transient failure between issue creation and label application cannot stall autonomous development permanently. **Superseded by** the OpenCode builder recorded in fragment 872; this is historical behavior, not the current handoff path.
- Added default-branch-only manual dispatch, least-privilege issue mutation, repository agent guidance, and conditional routing to authoritative research, design, and analytics tools for future product slices.
