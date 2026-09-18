import time
from appguardrail_core.language import LANGUAGE_BY_EXTENSION, PYTHON_MANIFESTS, JAVA_MANIFESTS, NODE_MANIFESTS

def fast_detect_language_axes(files):
    languages = set()
    seen_suffixes = set()
    seen_names = set()
    for file_path in files:
        if not isinstance(file_path, str):
            name = file_path.name
            suffix = file_path.suffix.lower()
        else:
            idx = max(file_path.rfind("/"), file_path.rfind("\\"))
            name = file_path[idx + 1 :] if idx != -1 else file_path

            dot_idx = name.rfind(".")
            suffix = name[dot_idx:].lower() if dot_idx > 0 else ""

        if suffix not in seen_suffixes:
            seen_suffixes.add(suffix)
            language = LANGUAGE_BY_EXTENSION.get(suffix)
            if language:
                languages.add(language)

        if name not in seen_names:
            seen_names.add(name)
            if name in PYTHON_MANIFESTS:
                languages.add("python")
            if name in JAVA_MANIFESTS:
                languages.add("java")
            if name in NODE_MANIFESTS:
                languages.add("javascript")
                if name == "tsconfig.json":
                    languages.add("typescript")

        # Stop early if we have found enough languages to max out typical rulesets
        if len(languages) >= 5:
            break
    return languages

def detect_language_axes(files):
    languages = set()
    for file_path in files:
        if not isinstance(file_path, str):
            name = file_path.name
            suffix = file_path.suffix.lower()
        else:
            idx = max(file_path.rfind("/"), file_path.rfind("\\"))
            name = file_path[idx + 1 :] if idx != -1 else file_path

            dot_idx = name.rfind(".")
            suffix = name[dot_idx:].lower() if dot_idx > 0 else ""

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
    candidates = ["src/file1.py", "src/file2.js", "src/file3.ts", "src/file4.go", "src/file5.rs", "test.xml", "test.yml"] * 100000

    start = time.time()
    for _ in range(10):
        detect_language_axes(candidates)
    print(f"Original: {time.time() - start:.4f}s")

    start = time.time()
    for _ in range(10):
        fast_detect_language_axes(candidates)
    print(f"Fast: {time.time() - start:.4f}s")

test_perf()
