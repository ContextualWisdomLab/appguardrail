### Changed

- The organization console now keeps in-flight (`aria-busy`) and temporarily unavailable (`aria-disabled` / native `disabled`) states distinct, shares `--busy-opacity` as the busy-state token, and blocks repeat scan-detail activation from both pointer and keyboard until the request finishes. Close, success, failure, and `finally` clear both attributes so a late response cannot leave a row looking disabled. Next: reuse the token list in `docs/storybook-inventory.md` for any new dashboard or Storybook surface; do not add a global `[aria-busy="true"]` rule.
