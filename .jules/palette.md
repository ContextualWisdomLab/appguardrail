## 2024-05-19 - Init Command UX Improvement
**Learning:** CLI outputs with inline repetitive warnings (e.g. `already contains rules — skipping`) can clutter terminal visibility and diminish developer experience.
**Action:** Group skipped/unchanged files separately from modified ones (e.g., in a single `Skipped (already configured):` section) to create clean, scannable terminal output.

## 2024-07-12 - Native Dialog Backdrop Pattern
**Learning:** The native `<dialog>` element provides a built-in way to detect backdrop clicks without extra backdrop wrappers or complex z-index management. Clicking the backdrop fires a click event where `e.target` is the dialog element itself, whereas clicking the modal content sets `e.target` to a child element.
**Action:** When using `<dialog>`, implement backdrop click-to-close with a simple `if (e.target === dialog) dialog.close()` listener to improve modal UX with zero dependencies.

## 2024-08-05 - Dynamic Rendering Cursor Position
**Learning:** When recreating input elements dynamically during client-side rendering (e.g. updating `innerHTML` after a search keystroke), re-focusing the element isn't enough. Simply placing the cursor at the end of the value disrupts users who are editing text in the middle of a string.
**Action:** Always capture `e.target.selectionStart` and `e.target.selectionEnd` before the DOM is replaced, and use `el.setSelectionRange(start, end)` after the element is re-rendered to maintain a seamless typing experience.

## 2026-08-01 - Dynamic filtering ARIA live regions and contextual ARIA labels
**Learning:** When creating interactive UI components like search-filterable tables, dynamically updating DOM structures are not announced to screen readers by default. Additionally, providing `role="button"` to elements like table rows masks their text content for some screen readers, requiring a fully descriptive `aria-label`.
**Action:** Always wrap dynamically changing content areas (like search results tables) in an `aria-live="polite"` region. When giving container elements (like `<tr>` or `<div>`) a `role="button"`, construct a dynamic `aria-label` that includes all necessary contextual text inside the container, as the implicit text node might be ignored.
