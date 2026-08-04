#!/usr/bin/env python3
"""Apply exact, bounded review fixes to the Code Scanning drift branch."""

from __future__ import annotations

from pathlib import Path


def replace_once(path_text: str, old: str, new: str) -> None:
    """Replace one exact reviewed source fragment and reject ambiguous drift."""
    path = Path(path_text)
    source = path.read_text(encoding="utf-8")
    if source.count(old) != 1:
        raise SystemExit(
            f"expected exactly one reviewed replacement in {path_text}: {old!r}"
        )
    path.write_text(source.replace(old, new), encoding="utf-8")


def main() -> int:
    """Apply every accepted current-head review finding exactly once."""
    replace_once(
        "CHANGELOG.d/862-code-scanning-analysis-drift.md",
        "Added a dependency-free exact 100% statement coverage gate",
        "Added an exact 100% statement coverage gate without coverage plugins",
    )
    replace_once(
        "docs/code-scanning-analysis-drift.md",
        "a dependency-free standard-library tracer",
        "a standard-library tracer without coverage plugins",
    )
    replace_once(
        "tests/test_code_scanning_core.py",
        'with pytest.raises(ValueError, match="tool.name"):',
        'with pytest.raises(ValueError, match=r"tool\\.name"):',
    )
    replace_once(
        "tests/test_code_scanning_drift_collector.py",
        'with pytest.raises(ValueError, match="api.github.com"):',
        'with pytest.raises(ValueError, match=r"api\\.github\\.com"):',
    )
    replace_once(
        "scripts/ci/collect_code_scanning_drift.py",
        '''    }
    return (
        f"{MARKER_PREFIX} "
        f"{json.dumps(payload, sort_keys=True, separators=(',', ':'))} "
        f"{MARKER_SUFFIX}"
    )''',
        r'''    }
    encoded = json.dumps(
        payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")
    ).replace(">", "\\u003e")
    return (
        f"{MARKER_PREFIX} "
        f"{encoded} "
        f"{MARKER_SUFFIX}"
    )''',
    )
    replace_once(
        "scripts/ci/collect_code_scanning_drift.py",
        '''        and issue.get("title")
        and "pull_request" not in issue''',
        '''        and issue.get("title")
        and isinstance(issue.get("number"), int)
        and not isinstance(issue.get("number"), bool)
        and issue["number"] > 0
        and "pull_request" not in issue''',
    )
    replace_once(
        "scripts/ci/collect_code_scanning_drift.py",
        '''        issues[title] = (
            created
            if isinstance(created, dict)
            else {"number": 0, "state": "open", "title": title, "body": body}
        )
        published += 1''',
        '''        if (
            isinstance(created, dict)
            and isinstance(created.get("number"), int)
            and not isinstance(created.get("number"), bool)
            and created["number"] > 0
        ):
            issues[title] = created
        published += 1''',
    )
    replace_once(
        "scripts/ci/verify_module_coverage.py",
        '''        total = len(target.executable)
        covered = len(target.executable & target.executed)
        if target.missing:''',
        '''        total = len(target.executable)
        covered = len(target.executable & target.executed)
        if total == 0:
            failures.append(f"{target.path}: no executable statement lines")
            continue
        if target.missing:''',
    )
    replace_once(
        ".github/workflows/tests.yml",
        '''            --test tests/test_code_scanning_page_result_issue_index.py \\
            --test tests/test_code_scanning_remaining_coverage.py''',
        '''            --test tests/test_code_scanning_page_result_issue_index.py \\
            --test tests/test_code_scanning_remaining_coverage.py \\
            --test tests/test_code_scanning_review_regressions.py''',
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
