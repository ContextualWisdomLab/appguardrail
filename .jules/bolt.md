## 2024-07-03 - Avoid `pathlib.Path` in tight loops
**Learning:** Instantiating `pathlib.Path` objects and calling their methods (like `relative_to`) in tight loops causes massive performance overhead due to repeated internal checks and tuple parsing.
**Action:** Use string manipulations (e.g., `startswith` and slicing) when evaluating relative paths inside file-scanning loops.
