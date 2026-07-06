## 2026-06-23 - Error message UX improvements
**Learning:** Error messages in CLIs should be explicit, use visual cues (like emojis for attention), and provide actionable hints when appropriate.
**Action:** When adding or modifying error messages in the CLI, use '❌ Error: [Message]' format and add '💡 Hint: [Actionable advice]' to help users resolve the issue easily.

## 2026-06-30 - Added Emojis to CLI Output Messages
**Learning:** Adding subtle emojis to informative CLI output headers (like "Created/updated files" and "Next steps") provides clearer visual cues for developers scanning long CLI output.
**Action:** Always include relevant emojis in summary output text to make success and informational messages more visually distinguishable from routine command logs.

## 2026-07-06 - Dynamic Element Keyboard Accessibility Pattern
**Learning:** Tables or lists rendered dynamically from JSON data often lack keyboard support. Screen reader users and keyboard navigators cannot interact with `<tr>` elements that rely solely on `click` event listeners.
**Action:** When adding interactivity to non-interactive elements like `<tr>` or `<div>`, always pair `click` listeners with `keydown` listeners (handling `Enter` and `Space`), and set `tabindex="0"`, `role="button"`, and contextual `aria-label`s. Ensure a global `:focus-visible` outline is available.
