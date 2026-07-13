## 2026-06-23 - Error message UX improvements
**Learning:** Error messages in CLIs should be explicit, use visual cues (like emojis for attention), and provide actionable hints when appropriate.
**Action:** When adding or modifying error messages in the CLI, use '❌ Error: [Message]' format and add '💡 Hint: [Actionable advice]' to help users resolve the issue easily.

## 2026-06-30 - Added Emojis to CLI Output Messages
**Learning:** Adding subtle emojis to informative CLI output headers (like "Created/updated files" and "Next steps") provides clearer visual cues for developers scanning long CLI output.
**Action:** Always include relevant emojis in summary output text to make success and informational messages more visually distinguishable from routine command logs.
## 2025-02-23 - Conditional Emoji Rendering for CLI Output
**Learning:** Hardcoded emojis in CLI headers can negatively impact automated log parsers and non-UTF8 legacy terminals. Removing non-ASCII chars broadly can strip valid accents like 'résumé'.
**Action:** When adding emojis to CLI interfaces for UX cues, implement a targeted regex (e.g., `[ℹ⏭⚙⚠⚡✅✨❌🌐🐍👋💡🔍🔎🔧🔴🔵🚀🛡🟠🟡🧩🧭🧾]`) and wrap `print` with a conditional output function like `_cprint` that checks an env var (e.g., `APPGUARDRAIL_NO_EMOJI`).
