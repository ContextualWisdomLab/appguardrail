### Added

- Added a reviewed hourly commercial-readiness loop that remains pull-request-first, dispatches at most one buyer-visible product gap through ordinary IssueOps, and preserves all existing review, check, and branch-protection gates.
- Added fail-closed recovery for interrupted issue-to-Jules handoffs so a transient failure between issue creation and label application cannot stall autonomous development permanently.
