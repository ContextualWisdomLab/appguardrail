## 2024-05-19 - Init Command UX Improvement
**Learning:** CLI outputs with inline repetitive warnings (e.g. `already contains rules — skipping`) can clutter terminal visibility and diminish developer experience.
**Action:** Group skipped/unchanged files separately from modified ones (e.g., in a single `Skipped (already configured):` section) to create clean, scannable terminal output.
## 2024-07-10 - Dashboard Single-File App Accessibility & Focus State UX
**Learning:** In zero-framework, single-file HTML applications, relying strictly on default browser focus states often results in poor keyboard accessibility for interactive elements like buttons inside dialogs, inputs, and custom table rows acting as buttons. A uniform focus style and missing ARIA associations can confuse screen readers.
**Action:** Always explicitly define a `:focus-visible` outline for `a, button, input, select` and add clear `aria-labelledby` linkages between a `<dialog>` and its title when implementing raw HTML components without a design system. Ensure custom interactable elements like `<tr role="button">` have rich `aria-label`s beyond generic text to provide context.
