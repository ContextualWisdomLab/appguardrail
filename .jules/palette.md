## 2024-05-19 - Init Command UX Improvement
**Learning:** CLI outputs with inline repetitive warnings (e.g. `already contains rules — skipping`) can clutter terminal visibility and diminish developer experience.
**Action:** Group skipped/unchanged files separately from modified ones (e.g., in a single `Skipped (already configured):` section) to create clean, scannable terminal output.

## 2024-07-12 - Native Dialog Backdrop Pattern
**Learning:** The native `<dialog>` element provides a built-in way to detect backdrop clicks without extra backdrop wrappers or complex z-index management. Clicking the backdrop fires a click event where `e.target` is the dialog element itself, whereas clicking the modal content sets `e.target` to a child element.
**Action:** When using `<dialog>`, implement backdrop click-to-close with a simple `if (e.target === dialog) dialog.close()` listener to improve modal UX with zero dependencies.

## 2024-08-05 - Dynamic Rendering Cursor Position
**Learning:** When recreating input elements dynamically during client-side rendering (e.g. updating `innerHTML` after a search keystroke), re-focusing the element isn't enough. Simply placing the cursor at the end of the value disrupts users who are editing text in the middle of a string.
**Action:** Always capture `e.target.selectionStart` and `e.target.selectionEnd` before the DOM is replaced, and use `el.setSelectionRange(start, end)` after the element is re-rendered to maintain a seamless typing experience.

## 2024-10-24 - Interactive Table Rows Keyboard Accessibility
**Learning:** Interactive table rows (e.g. `tr.scan` with `onclick` handlers) are not inherently accessible to keyboard users. Screen readers may ignore them, and they cannot be focused or activated via keyboard.
**Action:** When making table rows interactive, always add `tabindex="0"`, `role="button"`, an appropriate `aria-label`, and a `keydown` event listener to handle `Enter` and `Space` key presses.

## 2026-07-18 - 표준화된 에러 메시지와 동적 복수형 처리
**Learning:** CLI 도구에서 에러 메시지의 일관성(`❌ Error:`)과 실천 가능한 조언(`💡 Hint:`)의 명확한 구분은 사용자의 문제 해결 경험을 크게 향상시킨다. 또한 하드코딩된 복수형 접미사(예: `components`)는 터미널 출력의 품질을 떨어뜨린다.
**Action:** 향후 CLI 출력 메시지를 작성할 때, 반드시 일관된 접두어를 사용하고, 수량에 따른 단수/복수 처리를 삼항 연산자 등을 통해 동적으로 처리해야 한다.
