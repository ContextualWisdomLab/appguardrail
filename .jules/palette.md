## 2024-05-19 - Init Command UX Improvement
**Learning:** CLI outputs with inline repetitive warnings (e.g. `already contains rules — skipping`) can clutter terminal visibility and diminish developer experience.
**Action:** Group skipped/unchanged files separately from modified ones (e.g., in a single `Skipped (already configured):` section) to create clean, scannable terminal output.

## 2024-05-19 - Separating Deploy Blockers from Informational Warnings
**Learning:** Grouping non-blocking severity levels (WARNING, INFO) under a "Deploy blockers:" prefix creates user confusion, implying these low-priority items will fail CI pipelines or deployments.
**Action:** When summarizing severity counts, always separate critical/high issues from warnings/infos with clear labels (e.g. `| Other:` or `| Warnings & Info:`) to reinforce their non-blocking nature.
