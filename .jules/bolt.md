## 2024-07-06 - Replacing Path.relative_to with String Prefix Checking
**Learning:** In performance-critical loops (like file scanning in `scanner/cli/appguardrail.py`), using `pathlib.Path.relative_to()` has significant performance overhead compared to basic string manipulation, as noted in the prompt memories. `relative_to` can be about 150x slower than simple string slicing `startswith`.
**Action:** Replace `file_path.relative_to(resolved_base_path)` with string manipulations (e.g. prefix checking with `startswith` and slicing) to improve the performance of file scanning in the `_scan_file` function.

## 2024-07-06 - Replacing Path.relative_to with String Prefix Checking
**Learning:** In performance-critical loops (like file scanning in `scanner/cli/appguardrail.py`), using `pathlib.Path.relative_to()` has significant performance overhead compared to basic string manipulation, as noted in the prompt memories. `relative_to` can be about 150x slower than simple string slicing `startswith`. When a file exactly matches the base path, `pathlib.Path.relative_to` resolves to `"."` rather than an empty string `""`, so the string fallback must perfectly match this edge case.
**Action:** Replace `file_path.relative_to(resolved_base_path)` with string manipulations (e.g. prefix checking with `startswith` and slicing) to improve the performance of file scanning in the `_scan_file` function.

