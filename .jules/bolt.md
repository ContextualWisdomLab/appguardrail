## 2025-02-28 - Optimizing Python File Traversal
**Learning:** `os.walk` paired with `Path.is_file()` results in redundant system calls (`stat()`) for every discovered file, creating a significant performance bottleneck during directory traversal.
**Action:** Use `os.scandir` for recursive file collection instead. It reads directory entries and caches their type (file/directory) attributes, eliminating the need for separate `stat()` calls and doubling traversal speed.
