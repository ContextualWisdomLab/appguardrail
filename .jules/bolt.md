## 2024-05-18 - Optimize List Deduplication

**Learning:** When preserving insertion order during list deduplication in Python, iterating with a membership check (`if item not in list: list.append(item)`) causes O(N^2) complexity, creating a performance bottleneck when processing large numbers of elements.
**Action:** Use `dict.fromkeys(iterator)` to achieve O(N) complexity while perfectly preserving insertion order (supported in Python 3.7+).
