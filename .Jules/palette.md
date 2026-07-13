## 2026-06-23 - Error message UX improvements
**Learning:** Error messages in CLIs should be explicit, use visual cues (like emojis for attention), and provide actionable hints when appropriate.
**Action:** When adding or modifying error messages in the CLI, use '❌ Error: [Message]' format and add '💡 Hint: [Actionable advice]' to help users resolve the issue easily.

## 2026-06-30 - Added Emojis to CLI Output Messages
**Learning:** Adding subtle emojis to informative CLI output headers (like "Created/updated files" and "Next steps") provides clearer visual cues for developers scanning long CLI output.
**Action:** Always include relevant emojis in summary output text to make success and informational messages more visually distinguishable from routine command logs.

## 2024-07-08 - Conditionally disable CLI emojis
**Learning:** Heavy emoji usage in CLI tools can degrade accessibility for screen readers and cause issues in non-UTF8 terminals or log parsers.
**Action:** Implemented a targeted regex filter toggled by `APPGUARDRAIL_NO_EMOJI` to gracefully degrade CLI output without stripping valid international text, improving overall CLI UX and accessibility.

## 2026-07-06 - Clickable table rows and keyboard navigation
**Learning:** Treating standard `<tr>` elements as interactive clickable rows means they are ignored by screen readers and keyboard users unless specifically configured. Users relying on keyboards couldn't access finding details.
**Action:** When making custom non-interactive elements (like table rows or divs) clickable, always add `tabindex="0"`, a semantic `role="button"`, appropriate ARIA labels, and explicit `keydown` listeners for 'Enter' and 'Space' to support full accessibility.

## 2026-07-28 - Native HTML dialog accessibility and UX
**Learning:** Native HTML `<dialog>` elements do not automatically restore focus to the triggering element upon closure or close when the backdrop is clicked. This significantly breaks keyboard navigation flow for screen readers and power users.
**Action:** When implementing or modifying `<dialog>` elements, always manually capture the `document.activeElement` before calling `showModal()`, and restore focus to it via a `'close'` event listener. Also, add a `'click'` listener to the dialog to close it if `e.target === dialog` to support standard backdrop click UX.
