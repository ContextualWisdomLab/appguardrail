## 2024-05-19 - Init Command UX Improvement
**Learning:** CLI outputs with inline repetitive warnings (e.g. `already contains rules -- skipping`) can clutter terminal visibility and diminish developer experience.
**Action:** Group skipped/unchanged files separately from modified ones (e.g., in a single `Skipped (already configured):` section) to create clean, scannable terminal output.

## 2024-07-08 - Conditionally disable CLI emojis
**Learning:** Heavy emoji usage in CLI tools can degrade accessibility for screen readers and cause issues in non-UTF8 terminals or log parsers.
**Action:** Implement a targeted regex filter toggled by `APPGUARDRAIL_NO_EMOJI` to gracefully degrade CLI output without stripping valid international text.

## 2024-07-12 - Native Dialog Backdrop Pattern
**Learning:** The native `<dialog>` element provides a built-in way to detect backdrop clicks without extra wrappers or complex z-index management.
**Action:** Implement backdrop click-to-close with `if (e.target === dialog) dialog.close()` for better modal UX.

## 2024-07-13 - CLI 출력의 영문법적 복수형 및 에러 메시지 힌트 개선
**Learning:** CLI 출력에서 `file(s)`, `issue(s)`, `rule(s) excluded`와 같은 괄호 복수형은 가독성을 떨어뜨립니다. 또한 예외 메시지에 즉시 실행 가능한 힌트를 함께 제공하면 DX가 크게 향상됩니다.
**Action:** 조건부 f-string으로 복수형을 정확히 출력하고, 예외 로직에는 가능한 경우 `Hint`를 포함해 다음 액션을 안내합니다.

## 2024-07-28 - Accessibility improvements for tables and native dialogs
**Learning:** For screen readers, tables need explicit associations, and controls opening modals should indicate dialog behavior.
**Action:** Use `aria-haspopup="dialog"` on interactive rows, `scope="col"` on headers, and `aria-labelledby` with a concrete title id for `<dialog>`.

## 2024-08-05 - Dynamic Rendering Cursor Position
**Learning:** Re-focusing an input after dynamic `innerHTML` updates is not enough. Forcing the cursor to the end disrupts in-string edits.
**Action:** Capture `selectionStart` and `selectionEnd` before re-render, then restore with `setSelectionRange(start, end)`.

## 2026-07-06 - Clickable table rows and keyboard navigation
**Learning:** Clickable `<tr>` rows are ignored by keyboard and assistive tech without explicit semantics and keyboard handlers.
**Action:** Add `tabindex="0"`, `role="button"`, suitable ARIA labels, and `keydown` handlers for Enter/Space on custom interactive rows.

## 2026-07-28 - Native HTML dialog accessibility and UX
**Learning:** Native `<dialog>` does not automatically restore focus to the trigger and does not close on backdrop clicks by default.
**Action:** Save and restore `document.activeElement` around `showModal()`, and close when backdrop click target is the dialog element.

## 2024-07-24 - Screen Reader Announcements and Focus Restoration for Dynamic Filtering
**Learning:** When a UI like `scanner/dashboard/index.html` relies on full DOM replacement (`innerHTML`) during re-renders for filtering data, the dynamically injected elements (like the summary counts) aren't naturally announced to screen readers. Also, any interaction that triggers a re-render will cause the interactive element (like a select dropdown) to lose focus because it is destroyed and recreated.
**Action:** Always add `aria-live="polite"` to dynamically updated summary text to ensure changes are announced. Moreover, always explicitly restore focus to the triggering interactive element (e.g., `document.getElementById('id')?.focus()`) post-render to preserve keyboard accessibility.
