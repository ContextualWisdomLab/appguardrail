import time
import fnmatch
from functools import lru_cache

def _path_matches_glob(path: str, pattern: str) -> bool:
    """Match a normalized relative path against AppGuardrail rule globs."""
    path = path.replace("\\", "/")
    pattern = pattern.replace("\\", "/")
    if path.startswith("./"):
        path = path[2:]
    if pattern.startswith("./"):
        pattern = pattern[2:]
    if fnmatch.fnmatch(path, pattern):
        return True
    if pattern.startswith("**/") and fnmatch.fnmatch(path, pattern[3:]):
        return True
    return False

@lru_cache(maxsize=2048)
def _path_allowed_by_rule_cached(path: str, include_paths: tuple, exclude_paths: tuple) -> bool:
    if include_paths and not any(_path_matches_glob(path, glob) for glob in include_paths):
        return False
    if exclude_paths and any(_path_matches_glob(path, glob) for glob in exclude_paths):
        return False
    return True

def fast_path_allowed_by_rule_cached(path: str, include_paths: tuple, exclude_paths: tuple) -> bool:
    if include_paths:
        matched = False
        for glob in include_paths:
            if _path_matches_glob(path, glob):
                matched = True
                break
        if not matched:
            return False

    if exclude_paths:
        for glob in exclude_paths:
            if _path_matches_glob(path, glob):
                return False

    return True

# Simulate caching wrapper
def _path_allowed_by_rule(path, include_paths, exclude_paths):
    return fast_path_allowed_by_rule_cached(path, include_paths, exclude_paths)

def test_perf():
    include = ("src/**/*.py", "lib/**/*.py")
    exclude = ("tests/**/*.py", "vendor/**/*.py")

    start = time.time()
    for i in range(100000):
        # vary path to bypass cache
        _path_allowed_by_rule_cached.__wrapped__(f"src/file{i}.py", include, exclude)
    print(f"Original: {time.time() - start:.4f}s")

    start = time.time()
    for i in range(100000):
        fast_path_allowed_by_rule_cached(f"src/file{i}.py", include, exclude)
    print(f"Fast: {time.time() - start:.4f}s")

test_perf()
