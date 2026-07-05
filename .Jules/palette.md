## 2026-06-23 - Error message UX improvements
**Learning:** Error messages in CLIs should be explicit, use visual cues (like emojis for attention), and provide actionable hints when appropriate.
**Action:** When adding or modifying error messages in the CLI, use '❌ Error: [Message]' format and add '💡 Hint: [Actionable advice]' to help users resolve the issue easily.

## 2026-06-30 - Added Emojis to CLI Output Messages
**Learning:** Adding subtle emojis to informative CLI output headers (like "Created/updated files" and "Next steps") provides clearer visual cues for developers scanning long CLI output.
**Action:** Always include relevant emojis in summary output text to make success and informational messages more visually distinguishable from routine command logs.

## 2025-07-05 - Add emoji conditional rendering
**Learning:** When enhancing CLI Developer Experience (DX) output, use subtle emojis in informative headers for visual cues, but ensure they can be conditionally disabled to maintain compatibility with non-UTF8 locales, legacy terminals, and automated log parsers.
**Action:** Intercept standard library print to conditionally filter emojis based on APPGUARDRAIL_NO_EMOJI environment variable using a targeted regex instead of globally monkey patching or stripping all non-ASCII characters.
