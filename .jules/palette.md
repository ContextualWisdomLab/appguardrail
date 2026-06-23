## 2024-06-18 - Better Empty States
**Learning:** Empty states are a critical part of the user experience. A "0 files scanned" message without any guidance can be confusing and lead users to wonder if the tool is broken or if they ran it in the wrong place.
**Action:** Always provide actionable guidance in empty states. Added a helpful hint "Are you in the right directory?" when 0 files are scanned.

## 2024-06-22 - Precise Pluralization
**Learning:** Terminal output needs UX polish too. Small things like saying "1 files" or "1 warnings" can make a tool feel unrefined or hacked together. Proper pluralization increases trust in CLI tools.
**Action:** Always format counts with proper grammar (e.g., `warning` vs `warnings`) in CLI outputs to ensure a polished user experience.

## 2024-06-23 - Vertical Alignment for Readable CLI Output
**Learning:** Dense CLI output is hard to read quickly. When metadata is spread across lines with varying lengths, users struggle to scan for important details.
**Action:** Vertically align label prefixes (e.g., `Rule:    `, `Details: `, `Message: `) in multi-line text outputs to create a scannable grid that improves the developer experience.
