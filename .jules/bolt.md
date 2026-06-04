## 2024-05-24 - os.scandir Optimization
**Learning:** In Python CLIs that frequently scan directories (like the security scanner), `os.walk` combined with `Path` operations leads to redundant `stat()` system calls.
**Action:** Use `os.scandir` combined with `os.path.splitext` for fast extension checking, and defer `Path` creation until a file is actually needed for processing.
