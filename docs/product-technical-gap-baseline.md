# Product technical gap baseline

Status: Proposed
Predecessor pull request: #1342
Predecessor exact head reviewed: `8727f8901eb3152d7a69d2d7b09d2955829d349a`
Successor branch: `codex/design-assurance-appguardrail-1342-20260930`

## Goal and ownership

This successor preserves the valid documentation correction from #1342 and restores the deleted executable contract and evidence baseline. AppGuardrail remains the canonical writer for its dashboard UI and upload behavior.

## Context and acceptance matrix

| Capability | Current evidence | Status | Required action |
| --- | --- | --- | --- |
| File-upload semantics | Hidden native input is removed from the AOM; exposed proxy button triggers `fileInput.click()` | GREEN (source contract) | Keep focused test green at exact head |
| Keyboard and pointer activation | Proxy is a native button | NOT REVALIDATED | Verify keyboard, pointer, and touch in a real browser |
| Lifecycle and race safety | Existing async detail tests do not cover upload cancellation/retry lifecycle | FAIL | Add browser evidence for cancel, retry, stale response, and cleanup |
| Responsive layouts | No current-head desktop/mobile/intermediate screenshots | FAIL | Capture all three viewport classes |
| WCAG 2.2 AA | Semantic contract exists; axe and assistive-technology evidence absent | FAIL | Run axe plus keyboard/screen-reader audit |
| UI states | loading/empty/error/offline/permission/read-only/stale/conflict/retry/busy not evidenced for upload | FAIL | Add state stories or browser scenarios where applicable |
| Locales | ko/en/ja/zh/vi/es/de/fr evidence absent | FAIL | Connect versioned translation resources and locale E2E |
| Determinism, large data, import/export, recovery | Not changed by this focused documentation repair | NOT AFFECTED | Preserve existing domain and API contracts |

## Merge gate

Keep this PR Draft until exact-head Checks, browser interaction, responsive screenshots, accessibility evidence, locale coverage, and required review are green. The predecessor remains open; no valid delta is retired.
