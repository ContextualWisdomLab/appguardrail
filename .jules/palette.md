## 2024-05-19 - Init Command UX Improvement
**Learning:** CLI outputs with inline repetitive warnings (e.g. `already contains rules — skipping`) can clutter terminal visibility and diminish developer experience.
**Action:** Group skipped/unchanged files separately from modified ones (e.g., in a single `Skipped (already configured):` section) to create clean, scannable terminal output.

## 2024-07-07 - Interactive Table Row Accessibility
**Learning:** Interactive `<tr data-i>` rows triggered purely via JS `click` handlers are entirely invisible to keyboard navigation, leaving a crucial UX gap for power users and accessibility devices.
**Action:** Always complement `click` listeners on non-standard interactive elements with explicit `tabindex="0"`, `role="button"`, `:focus-visible` styles, and a `keydown` handler listening for `Enter` and `Space` to guarantee fully accessible, predictable interactions.
