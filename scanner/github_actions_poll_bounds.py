"""Structural GitHub Actions polling-bound analysis for security issue #1087.

The detector intentionally supports the conventional literal-shell workflow
shape used by the verified ContextualWisdomLab/.github incident.  It models
job, run-block, loop, retry-budget, and loop-local termination state instead of
combining file-wide regular-expression evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
import re


HISTORICAL_RULE_ID = "github-actions-transport-only-poll-bound"
GENERIC_RULE_ID = "github-actions-transport-failure-budget-poll-bound"
POLL_BOUND_RULE_IDS = frozenset({HISTORICAL_RULE_ID, GENERIC_RULE_ID})

_JOB_HEADER = re.compile(r"^  [A-Za-z0-9_.-]+:[^\n]*$")
_JOB_TIMEOUT = re.compile(
    r"^    timeout-minutes[ \t]*:[ \t]*[1-9][0-9]*[ \t]*(?:#[^\n]*)?$"
)
_RUN_HEADER = re.compile(
    r"^(?:      -[ \t]*run|        run)[ \t]*:[ \t]*\|[+-]?[ \t]*(?:#[^\n]*)?$"
)
_WHILE_HEADER = re.compile(r"^          while[ \t]+(?::|true)[ \t]*;[ \t]*do(?:[ \t]*#[^\n]*)?$")
_DONE = re.compile(r"^          done\b")
_TOP_ASSIGNMENT = re.compile(
    r"^          (?P<name>[A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(?P<value>[^\n]*?)"
    r"[ \t]*(?:#[^\n]*)?$"
)
_POSITIVE_INT = re.compile(r"^[1-9][0-9]*$")
_ZERO = re.compile(r"^0$")
_DIRECT_SLEEP = re.compile(r"^            sleep(?:[ \t]+|$)")
_DIRECT_TERMINATION = re.compile(
    r"^            (?:break(?:[ \t]+[0-9]+)?|exit[ \t]+0)[ \t]*(?:#[^\n]*)?$"
)
_FAILURE_IF = re.compile(r"^            if[ \t]+![^\n]*\bgh[ \t]+api\b[^\n]*;[ \t]*then")
_DIRECT_FI = re.compile(r"^            fi[ \t]*(?:#[^\n]*)?$")
_INCREMENT = re.compile(
    r"^(?P<indent> {12,})(?P<name>[A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*"
    r"\$\(\([ \t]*(?P=name)[ \t]*\+[ \t]*1[ \t]*\)\)[ \t]*(?:#[^\n]*)?$"
)
_LIMIT_GUARD = re.compile(
    r"^(?P<indent> {12,})if\b[^\n]*\$(?P<counter>[A-Za-z_][A-Za-z0-9_]*)"
    r"[^\n]*-ge[^\n]*\$(?P<limit>[A-Za-z_][A-Za-z0-9_]*)\b[^\n]*;[ \t]*then"
)
_NONZERO_EXIT = re.compile(r"^(?P<indent> +)exit[ \t]+[1-9][0-9]*\b")
_DEADLINE_GUARD = re.compile(
    r"^            if\b[^\n]*\bdate\b[^\n]*\+%s[^\n]*-[gl]e[^\n]*"
    r"\$(?:\{)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:\})?\b[^\n]*;[ \t]*then"
)
_DEADLINE_INIT = re.compile(
    r"^\$\(\([^\n]*\bdate\b[^\n]*\+%s[^\n]*\+[ \t]*[1-9][0-9]*[ \t]*\)\)$"
)
_DIRECT_TOTAL_INCREMENT = re.compile(
    r"^            (?P<name>[A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*"
    r"\$\(\([ \t]*(?P=name)[ \t]*\+[ \t]*1[ \t]*\)\)[ \t]*(?:#[^\n]*)?$"
)
_DIRECT_TOTAL_GUARD = re.compile(
    r"^            if\b[^\n]*\$(?P<counter>[A-Za-z_][A-Za-z0-9_]*)"
    r"[^\n]*-ge[^\n]*\$(?P<limit>[A-Za-z_][A-Za-z0-9_]*)\b[^\n]*;[ \t]*then"
)


@dataclass(frozen=True, slots=True)
class PollBoundMatch:
    """One executable polling-bound finding and its source character offset."""

    rule_id: str
    start_index: int


@dataclass(frozen=True, slots=True)
class _SourceLine:
    """One source line without its newline plus the original character offset."""

    text: str
    start_index: int


def _source_lines(content: str) -> list[_SourceLine]:
    """Split source text while preserving stable character offsets."""
    lines: list[_SourceLine] = []
    offset = 0
    for raw in content.splitlines(keepends=True):
        text = raw.rstrip("\r\n")
        lines.append(_SourceLine(text=text, start_index=offset))
        offset += len(raw)
    if content and (not lines or offset < len(content)):
        lines.append(_SourceLine(text=content[offset:], start_index=offset))
    return lines


def _indent(text: str) -> int:
    """Return leading-space indentation; tabs remain outside reviewed grammar."""
    return len(text) - len(text.lstrip(" "))


def _job_ranges(lines: list[_SourceLine]):
    """Yield conventional two-space job blocks without crossing top-level YAML."""
    starts = [index for index, line in enumerate(lines) if _JOB_HEADER.match(line.text)]
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        for index in range(start + 1, end):
            text = lines[index].text
            if text and _indent(text) == 0:
                end = index
                break
        yield start, end


def _run_ranges(lines: list[_SourceLine], start: int, end: int):
    """Yield literal-shell run-block content ranges within one conventional job."""
    index = start + 1
    while index < end:
        if not _RUN_HEADER.match(lines[index].text):
            index += 1
            continue
        body_start = index + 1
        body_end = body_start
        while body_end < end:
            text = lines[body_end].text
            if text and _indent(text) < 10:
                break
            body_end += 1
        yield body_start, body_end
        index = max(body_end, index + 1)


def _loop_ranges(lines: list[_SourceLine], start: int, end: int):
    """Yield top-level shell while/done pairs from one literal run block."""
    index = start
    while index < end:
        if not _WHILE_HEADER.match(lines[index].text):
            index += 1
            continue
        done = index + 1
        while done < end and not _DONE.match(lines[done].text):
            done += 1
        if done >= end:
            return
        yield index, done
        index = done + 1


def _assignments_before(
    lines: list[_SourceLine], start: int, end: int
) -> dict[str, str]:
    """Return the last top-level shell assignment for each identifier."""
    assignments: dict[str, str] = {}
    for index in range(start, end):
        match = _TOP_ASSIGNMENT.match(lines[index].text)
        if match:
            assignments[match.group("name")] = match.group("value").strip()
    return assignments


def _executable_gh_api(text: str) -> bool:
    """Return whether a shell line executes gh api rather than merely quoting it."""
    stripped = text.lstrip(" ")
    if "gh api" not in stripped or stripped.startswith(("#", "echo ", "printf ")):
        return False
    if re.match(r"^(?:timeout[ \t]+\S+[ \t]+)?gh[ \t]+api\b", stripped):
        return True
    if re.match(r"^if[ \t]+!", stripped) and re.search(r"\bgh[ \t]+api\b", stripped):
        return True
    return bool(
        re.match(r"^[A-Za-z_][A-Za-z0-9_]*[ \t]*=", stripped)
        and "$(`" not in stripped
        and re.search(r"\$\([^\n]*\bgh[ \t]+api\b", stripped)
    )


def _matching_direct_fi(lines: list[_SourceLine], if_index: int, done: int) -> int | None:
    """Return the direct loop-body fi that closes a direct if statement."""
    for index in range(if_index + 1, done):
        if _DIRECT_FI.match(lines[index].text):
            return index
    return None


def _guard_exits_nonzero(
    lines: list[_SourceLine], guard_index: int, end: int, guard_indent: int
) -> bool:
    """Return whether a reviewed shell guard fails closed with a nonzero exit."""
    for index in range(guard_index + 1, end):
        text = lines[index].text
        indent = _indent(text)
        if text and indent <= guard_indent:
            break
        match = _NONZERO_EXIT.match(text)
        if match and len(match.group("indent")) > guard_indent:
            return True
    return False


def _safe_deadline(
    lines: list[_SourceLine], loop_start: int, gh_index: int, assignments: dict[str, str]
) -> bool:
    """Recognize a causally initialized, loop-local fail-closed wall-clock bound."""
    for index in range(loop_start + 1, gh_index):
        match = _DEADLINE_GUARD.match(lines[index].text)
        if not match or not _guard_exits_nonzero(lines, index, gh_index, 12):
            continue
        initialized = assignments.get(match.group("name"), "")
        if _DEADLINE_INIT.match(initialized):
            return True
    return False


def _safe_total_attempts(
    lines: list[_SourceLine], loop_start: int, gh_index: int, assignments: dict[str, str]
) -> bool:
    """Recognize a loop-wide attempt counter that fails closed before remote polling."""
    increments: dict[str, int] = {}
    for index in range(loop_start + 1, gh_index):
        increment = _DIRECT_TOTAL_INCREMENT.match(lines[index].text)
        if increment:
            increments[increment.group("name")] = index
            continue
        guard = _DIRECT_TOTAL_GUARD.match(lines[index].text)
        if not guard:
            continue
        counter = guard.group("counter")
        limit = guard.group("limit")
        if increments.get(counter, gh_index) >= index:
            continue
        if not _ZERO.match(assignments.get(counter, "")):
            continue
        if not _POSITIVE_INT.match(assignments.get(limit, "")):
            continue
        if _guard_exits_nonzero(lines, index, gh_index, 12):
            return True
    return False


def _repeatable_healthy_path(
    lines: list[_SourceLine], start: int, done: int
) -> bool:
    """Require a direct sleep/back-edge path not dominated by unconditional success exit."""
    for index in range(start, done):
        text = lines[index].text
        if _DIRECT_TERMINATION.match(text):
            return False
        if _DIRECT_SLEEP.match(text):
            return True
    return False


def _generic_failure_pair(
    lines: list[_SourceLine], loop_start: int, done: int, assignments: dict[str, str]
) -> tuple[int, int] | None:
    """Return the causal failing-gh branch and its closing fi for a retry budget."""
    for if_index in range(loop_start + 1, done):
        if not _FAILURE_IF.match(lines[if_index].text):
            continue
        fi_index = _matching_direct_fi(lines, if_index, done)
        if fi_index is None:
            continue
        increments: set[str] = set()
        for index in range(if_index + 1, fi_index):
            increment = _INCREMENT.match(lines[index].text)
            if increment:
                increments.add(increment.group("name"))
                continue
            guard = _LIMIT_GUARD.match(lines[index].text)
            if not guard or guard.group("counter") not in increments:
                continue
            counter = guard.group("counter")
            limit = guard.group("limit")
            if not _ZERO.match(assignments.get(counter, "")):
                continue
            if not _POSITIVE_INT.match(assignments.get(limit, "")):
                continue
            if _guard_exits_nonzero(lines, index, fi_index, _indent(lines[index].text)):
                return if_index, fi_index
    return None


def _historical_match(
    lines: list[_SourceLine], run_start: int, loop_start: int, done: int
) -> PollBoundMatch | None:
    """Detect the pinned max_poll_transport_failures incident family."""
    assignments = _assignments_before(lines, run_start, loop_start)
    if not _POSITIVE_INT.match(assignments.get("max_poll_transport_failures", "")):
        return None
    gh_index = next(
        (
            index
            for index in range(loop_start + 1, done)
            if _executable_gh_api(lines[index].text)
        ),
        None,
    )
    if gh_index is None:
        return None
    if _safe_deadline(lines, loop_start, gh_index, assignments):
        return None
    if _safe_total_attempts(lines, loop_start, gh_index, assignments):
        return None
    if not _repeatable_healthy_path(lines, gh_index + 1, done):
        return None
    return PollBoundMatch(HISTORICAL_RULE_ID, lines[loop_start].start_index)


def _generic_match(
    lines: list[_SourceLine], run_start: int, loop_start: int, done: int
) -> PollBoundMatch | None:
    """Detect renamed transport-failure budgets with an unbounded healthy path."""
    assignments = _assignments_before(lines, run_start, loop_start)
    if "max_poll_transport_failures" in assignments:
        return None
    failure = _generic_failure_pair(lines, loop_start, done, assignments)
    if failure is None:
        return None
    gh_index, fi_index = failure
    if _safe_deadline(lines, loop_start, gh_index, assignments):
        return None
    if _safe_total_attempts(lines, loop_start, gh_index, assignments):
        return None
    if not _repeatable_healthy_path(lines, fi_index + 1, done):
        return None
    return PollBoundMatch(GENERIC_RULE_ID, lines[loop_start].start_index)


def iter_poll_bound_matches(content: str) -> tuple[PollBoundMatch, ...]:
    """Return structural #1087 findings for conventional literal-shell workflows."""
    if "gh api" not in content or "while" not in content or "sleep" not in content:
        return ()
    lines = _source_lines(content)
    findings: list[PollBoundMatch] = []
    for job_start, job_end in _job_ranges(lines):
        if any(_JOB_TIMEOUT.match(lines[index].text) for index in range(job_start, job_end)):
            continue
        for run_start, run_end in _run_ranges(lines, job_start, job_end):
            for loop_start, done in _loop_ranges(lines, run_start, run_end):
                historical = _historical_match(lines, run_start, loop_start, done)
                if historical is not None:
                    findings.append(historical)
                    continue
                generic = _generic_match(lines, run_start, loop_start, done)
                if generic is not None:
                    findings.append(generic)
    return tuple(findings)
