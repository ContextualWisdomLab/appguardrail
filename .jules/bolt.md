## 2024-07-05 - Pathlib Performance Overhead in Hot Loops
**Learning:** `pathlib.Path.relative_to()` has significant performance overhead in tight loops because of internal OS and logic paths, as observed in `scanner/cli/appguardrail.py` file scanning.
**Action:** Replace expensive `pathlib` method calls inside hot loops with string manipulation functions like `startswith` and slicing.
