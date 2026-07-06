## 2024-05-19 - Init Command UX Improvement
**Learning:** CLI outputs with inline repetitive warnings (e.g. `already contains rules — skipping`) can clutter terminal visibility and diminish developer experience.
**Action:** Group skipped/unchanged files separately from modified ones (e.g., in a single `Skipped (already configured):` section) to create clean, scannable terminal output.

## 2024-07-06 - AppGuardrail Dashboard Keyboard Accessibility
**Learning:** The AppGuardrail dashboard (`scanner/dashboard/index.html`) lacked comprehensive keyboard accessibility. Key interactive elements (like finding rows) were `<tr>` tags with `click` listeners but no `tabindex` or `keydown` listeners. Furthermore, form elements lacked `aria-label`s, and there was no visual indicator for keyboard focus (`:focus-visible`).
**Action:** When adding or auditing custom interactive elements (like clickable table rows) in raw HTML/JS interfaces without a framework, always add `tabindex="0"`, a corresponding `keydown` listener for Enter/Space (`e.key === 'Enter' || e.key === ' '`), global `:focus-visible` styles, and `aria-label`s to visually unlabeled form inputs.
