import time
from appguardrail_core.language import detect_language_axes

def fast_detect_language_axes(files):
    languages = set()
    found_exts = set()
    for file_path in files:
        if not isinstance(file_path, str):
            name = file_path.name
            suffix = file_path.suffix.lower()
        else:
            idx = max(file_path.rfind("/"), file_path.rfind("\\"))
            name = file_path[idx + 1 :] if idx != -1 else file_path

            dot_idx = name.rfind(".")
            suffix = name[dot_idx:].lower() if dot_idx > 0 else ""

        # Optimization here
        language = LANGUAGE_BY_EXTENSION.get(suffix)
        if language:
            languages.add(language)
        if name in PYTHON_MANIFESTS:
            languages.add("python")
        if name in JAVA_MANIFESTS:
            languages.add("java")
        if name in NODE_MANIFESTS:
            languages.add("javascript")
            if name == "tsconfig.json":
                languages.add("typescript")
    return languages

def test_perf():
    candidates = ["src/file1.py", "src/file2.js", "src/file3.ts", "src/file4.go", "src/file5.rs"] * 100000

    start = time.time()
    for _ in range(10):
        detect_language_axes(candidates)
    print(f"Original: {time.time() - start:.4f}s")

test_perf()
