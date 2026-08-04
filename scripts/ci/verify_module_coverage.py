#!/usr/bin/env python3
"""Verify exact statement coverage for reviewed production modules without plugins."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys
import trace
from typing import Iterable


@dataclass(frozen=True)
class CoverageTarget:
    """Executable and observed statement lines for one production module."""

    path: Path
    executable: frozenset[int]
    executed: frozenset[int]

    @property
    def missing(self) -> tuple[int, ...]:
        """Return unexecuted statement lines in deterministic order."""
        return tuple(sorted(self.executable - self.executed))


def executable_lines(path: Path) -> frozenset[int]:
    """Return executable source lines excluding explicit reviewed no-cover lines."""
    resolved = path.resolve()
    source_lines = resolved.read_text(encoding="utf-8").splitlines()
    discovered = trace._find_executable_linenos(str(resolved))  # noqa: SLF001
    return frozenset(
        line_number
        for line_number in discovered
        if 1 <= line_number <= len(source_lines)
        and "# pragma: no cover" not in source_lines[line_number - 1]
    )


def verify_coverage(targets: Iterable[CoverageTarget]) -> None:
    """Raise when any target is below exact, unrounded 100% statement coverage."""
    failures: list[str] = []
    for target in targets:
        total = len(target.executable)
        covered = len(target.executable & target.executed)
        if target.missing:
            failures.append(
                f"{target.path}: {covered}/{total}; missing lines "
                + ",".join(str(line) for line in target.missing)
            )
        else:
            print(f"100% statement coverage: {target.path} ({covered}/{total})")
    if failures:
        raise RuntimeError(
            "100% statement coverage is required:\n" + "\n".join(failures)
        )


def _execute_tests(test_paths: list[str]) -> dict[tuple[str, int], int]:
    """Run focused pytest files under the standard-library line tracer."""
    import pytest

    ignoredirs = tuple(
        str(Path(directory).resolve())
        for directory in {sys.prefix, sys.exec_prefix}
        if directory
    )
    tracer = trace.Trace(
        count=True,
        trace=False,
        ignoredirs=ignoredirs,
    )
    exit_code = tracer.runfunc(pytest.main, ["-q", *test_paths])
    if exit_code != 0:
        raise RuntimeError(f"focused coverage tests failed with exit code {exit_code}")
    return dict(tracer.results().counts)


def measure_coverage(
    module_paths: Iterable[Path], counts: dict[tuple[str, int], int]
) -> tuple[CoverageTarget, ...]:
    """Build exact coverage targets from traced filename and line counts."""
    executed_by_path: dict[Path, set[int]] = {}
    for (filename, line_number), count in counts.items():
        if count <= 0:
            continue
        path = Path(filename).resolve()
        executed_by_path.setdefault(path, set()).add(line_number)

    targets: list[CoverageTarget] = []
    for module_path in module_paths:
        resolved = module_path.resolve()
        targets.append(
            CoverageTarget(
                path=resolved,
                executable=executable_lines(resolved),
                executed=frozenset(executed_by_path.get(resolved, set())),
            )
        )
    return tuple(targets)


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse repeated production-module and focused-test path arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", dest="modules", action="append", required=True)
    parser.add_argument("--test", dest="tests", action="append", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run focused tests and enforce exact statement coverage for every module."""
    args = parse_args(sys.argv[1:] if argv is None else argv)
    module_paths = [Path(path) for path in args.modules]
    missing_paths = [str(path) for path in module_paths if not path.is_file()]
    missing_tests = [path for path in args.tests if not Path(path).is_file()]
    if missing_paths or missing_tests:
        raise SystemExit(
            "coverage inputs are missing: "
            + ", ".join((*missing_paths, *missing_tests))
        )
    counts = _execute_tests(args.tests)
    verify_coverage(measure_coverage(module_paths, counts))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
