## 2026-06-23 - Error message UX improvements
**Learning:** Error messages in CLIs should be explicit, use visual cues (like emojis for attention), and provide actionable hints when appropriate.
**Action:** When adding or modifying error messages in the CLI, use '❌ Error: [Message]' format and add '💡 Hint: [Actionable advice]' to help users resolve the issue easily.

## 2026-06-30 - Added Emojis to CLI Output Messages
**Learning:** Adding subtle emojis to informative CLI output headers (like "Created/updated files" and "Next steps") provides clearer visual cues for developers scanning long CLI output.
**Action:** Always include relevant emojis in summary output text to make success and informational messages more visually distinguishable from routine command logs.

## 2026-07-07 - Keyboard Accessible Clickable Rows
**Learning:** In the vanilla HTML dashboard (`scanner/dashboard/index.html`), interactive `<tr>` elements relied exclusively on a mouse `click` listener. For dynamically generated rows, accessibility requires not just `tabindex="0"` and a `role="button"`, but also an explicit `keydown` listener specifically checking for `Enter` or `Space` to trigger the default action while calling `e.preventDefault()` on the Space key to prevent page scroll.
**Action:** Whenever implementing non-native interactive elements (like rows acting as buttons), always couple the `click` event with a `keydown` handler and visual `:focus-visible` states to ensure full screen reader and keyboard navigability.
