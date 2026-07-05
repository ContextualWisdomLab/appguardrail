## 2026-06-23 - Error message UX improvements
**Learning:** Error messages in CLIs should be explicit, use visual cues (like emojis for attention), and provide actionable hints when appropriate.
**Action:** When adding or modifying error messages in the CLI, use '❌ Error: [Message]' format and add '💡 Hint: [Actionable advice]' to help users resolve the issue easily.

## 2026-06-30 - Added Emojis to CLI Output Messages
**Learning:** Adding subtle emojis to informative CLI output headers (like "Created/updated files" and "Next steps") provides clearer visual cues for developers scanning long CLI output.
**Action:** Always include relevant emojis in summary output text to make success and informational messages more visually distinguishable from routine command logs.
## 2026-07-05 - AppGuardrail CLI Emoji Formatting\n**Learning:** CLI output is significantly more scannable and accessible when Errors, Warnings, and file lists consistently use semantic prefixing combined with emojis (e.g. '❌ Error', '⚠️  Warning'). Adding '💡 Hint:' lines to errors reduces user friction.\n**Action:** Ensure all future CLI text changes or additions follow these exact structural and visual guidelines.
