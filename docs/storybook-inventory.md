# Storybook inventory — organization console

**Status:** Accepted inventory for reusable console objects  
**Last reviewed:** 2026-08-16

The live console is `scanner/dashboard/console.html`. It must keep working as a standalone no-build page. Use this inventory when adding a Storybook story or another dashboard surface so the same tokens and states are reused.

## Design tokens

| Token | Current value | Use this when |
|---|---|---|
| `--busy-opacity` | `.6` | Any in-flight or temporarily unavailable control |
| `--primary` | `#256EF4` | Focus rings and primary actions |
| `--muted` | `#5B6472` | Secondary text and close-button rest state |
| `--crit` | `#D93B3B` | Blocking counts and error text |
| `--radius` | `12px` | Cards and stat tiles |

Do not embed a one-off opacity or cursor in a new selector. Add a token here first.

## Stories to implement

| Story | Object | Required attributes | Buyer-visible next action |
|---|---|---|---|
| `Connect/Default` | `#connect` | none | Paste an org API key and connect |
| `Connect/Busy` | `#connect` | `aria-busy="true"` plus native `disabled` | Wait; the control is connecting |
| `ScanRow/Default` | `tr.scan` | `tabindex="0" role="button"` | Open scan details |
| `ScanRow/BusyUnavailable` | `tr.scan` | `aria-busy="true"` and `aria-disabled="true"` | Wait; do not activate again |
| `Detail/Loading` | `#detail` | polite live region only | Wait for findings; close stays available |
| `Detail/Error` | `#detail` | `role="alert"` | Read the error, then close or retry another row |

## Interaction contract

- Busy is progress. Unavailable is `aria-disabled` or native `disabled`.
- Pointer and keyboard (Enter/Space) must share one activation gate.
- Close and Escape must clear both attributes on the trigger and restore focus.
- A future busy parent must not apply `pointer-events: none` to `.close-btn`.

## Optional Storybook package

If a later change adds Storybook, ship it as an optional `@appguardrail/console-stories` (or equivalent) package that imports these tokens. Do not add a bundler to `appguardrail serve`. After adding a story, update this table and keep the contract tests in `tests/test_console_detail_loading_contract.py` as the executable source of truth.

## References (APA 7th)

World Wide Web Consortium. (2023a). *Accessible Rich Internet Applications (WAI-ARIA) 1.2*. https://www.w3.org/TR/wai-aria-1.2/

World Wide Web Consortium. (2023b). *Web Content Accessibility Guidelines (WCAG) 2.2*. https://www.w3.org/TR/WCAG22/
