## 2024-05-19 - Init Command UX Improvement
**Learning:** CLI outputs with inline repetitive warnings (e.g. `already contains rules — skipping`) can clutter terminal visibility and diminish developer experience.
**Action:** Group skipped/unchanged files separately from modified ones (e.g., in a single `Skipped (already configured):` section) to create clean, scannable terminal output.

## 2024-07-08 - Keyboard accessibility for interactive table rows
**Learning:** Table rows (`<tr>`) that act as clickable buttons (`cursor:pointer` with `click` listeners) are completely inaccessible to keyboard users unless explicitly made focusable and operable.
**Action:** When making non-standard interactive elements clickable, always add `tabindex="0"`, a `keydown` listener for 'Enter' and 'Space', and visible focus styles (`:focus-visible`) to ensure full keyboard operability.
