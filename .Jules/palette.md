## 2024-07-26 - Keyboard accessibility and DOM replacement
**Learning:** Because the UI relies on full DOM replacement (`innerHTML`) during re-renders (e.g., when filtering), keyboard focus is lost. Also, dynamic summary text needs `aria-live="polite"` to announce state changes (like filtered result counts) to screen readers.
**Action:** Always explicitly restore focus to interactive elements (e.g., `document.getElementById('id')?.focus()`) post-render if they trigger a re-render. Always use `aria-live="polite"` on dynamic summary text like filtered counts.
