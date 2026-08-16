# ADR-0007: Console busy and unavailable tokens stay scoped

**Status:** Accepted  
**Date:** 2026-08-16

## Context

The organization console is a standalone, no-build HTML page. Sighted and assistive-technology users need distinct feedback while a scan-detail request is in flight. A previous Palette change styled every `[aria-busy="true"]` element as disabled and applied `pointer-events: none`, which blocked pointer input while keyboard activation remained live and would also disable a future busy detail panel, including its close control.

WAI-ARIA 1.2 defines `aria-busy` as an in-flight update state and `aria-disabled` as perceivable-but-not-operable (World Wide Web Consortium, 2023a). Those states must not be conflated.

Repeated console surfaces (Connect, scan rows, detail close) also need a reusable token list so dashboard and a later Storybook package can share one busy/unavailable contract without forcing a JavaScript build into the standalone page.

## Decision

1. Native `disabled` buttons and `tr.scan[aria-disabled="true"]` share unavailable styling and pointer suppression.
2. `#connect[aria-busy="true"]` and `tr.scan[aria-busy="true"]` share a progress visual only. Busy-only rules MUST NOT set `pointer-events: none`.
3. `--busy-opacity` is the shared design token for both states.
4. `detail()` refuses repeat activation while the row is `aria-disabled`. Success, failure, close, and `finally` clear both attributes. Close also clears `lastDetailFocus` so a late `finally` cannot revive the row.
5. The standalone console remains ponytail: no framework and no build step. Storybook consumption is documented in `docs/storybook-inventory.md` and may later live in an optional package. It must not become a runtime dependency of `appguardrail serve`.

## Consequences

- Contract tests pin the scoped selectors, the busy-rule exclusion of `pointer-events`, and the close-path `aria-disabled` clear.
- A later busy `#detail` region can keep its close button operable.
- Adding `@storybook/html` requires a separate optional package and an inventory update; it is not a merge requirement for this console contract.

## Next action

Reuse `--busy-opacity` and the inventory stories when the next dashboard or Storybook surface needs an in-flight or unavailable control. Do not add a global `[aria-busy="true"]` rule.

## References (APA 7th)

World Wide Web Consortium. (2023a). *Accessible Rich Internet Applications (WAI-ARIA) 1.2*. https://www.w3.org/TR/wai-aria-1.2/

World Wide Web Consortium. (2023b). *Web Content Accessibility Guidelines (WCAG) 2.2*. https://www.w3.org/TR/WCAG22/
