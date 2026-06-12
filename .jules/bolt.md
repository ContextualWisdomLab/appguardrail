## 2024-05-24 - File traversal performance
**Learning:** When optimizing os.walk combined with Path objects, replacing them with os.scandir and os.path.splitext reduces stat() calls drastically, but requires careful matching of symlink behavior (os.walk matches directory symlinks depending on arguments, Path.is_file() follows symlinks by default).
**Action:** Use entry.is_dir(follow_symlinks=False) to match os.walk and entry.is_file() to match Path.is_file() default.

## 2025-02-28 - Optimizing Python File Traversal
**Learning:** `os.walk` paired with `Path.is_file()` can create redundant `stat()` calls during large scans.
**Action:** Prefer the existing `os.scandir` traversal with explicit symlink skipping and `follow_symlinks=False` checks so performance improvements do not weaken scanner boundaries.
