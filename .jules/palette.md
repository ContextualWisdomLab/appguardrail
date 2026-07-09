## 2024-05-19 - Init Command UX Improvement
**Learning:** CLI outputs with inline repetitive warnings (e.g. `already contains rules — skipping`) can clutter terminal visibility and diminish developer experience.
**Action:** Group skipped/unchanged files separately from modified ones (e.g., in a single `Skipped (already configured):` section) to create clean, scannable terminal output.

## 2025-07-09 - Accessibility for Table Rows in the Finding Dashboard
**Learning:** Adding `tabindex="0"` to interactive `<tr>` elements makes them focusable, but they require keyboard event handlers (`keydown` for Enter and Space) and ARIA labels to be fully usable by screen readers and keyboard users. Additionally, visible focus styles (`:focus-visible`) are essential for keyboard navigation UX.
**Action:** Always add keyboard event handlers and visual focus indicators when making custom non-interactive elements (like table rows) interactive.
