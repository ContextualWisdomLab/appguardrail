## 2024-05-24 - File traversal performance
**Learning:** When optimizing os.walk combined with Path objects, replacing them with os.scandir and os.path.splitext reduces stat() calls drastically, but requires careful matching of symlink behavior (os.walk matches directory symlinks depending on arguments, Path.is_file() follows symlinks by default).
**Action:** Use entry.is_dir(follow_symlinks=False) to match os.walk and entry.is_file() to match Path.is_file() default.
## 2024-05-24 - File scanning regex caching
**Learning:** In the Python scanner, dynamically building `applicable_rules` and looking up the `search` method (`rule["pattern"].search`) on every line incurs significant overhead in tight loops. However, naively combining regex patterns using `|` is dangerous due to backreference conflicts and capturing group limits.
**Action:** Optimize tight scanning loops by caching applicable rules per extension and pre-extracting the `.search` function references. Avoid concatenating complex regexes unless strictly required.
