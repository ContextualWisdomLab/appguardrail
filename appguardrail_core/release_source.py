"""Bounded, dependency-free release-source policy matcher for block workflows.

This is a source-policy warning, not proof that PyPI accepts an upload. The
supported syntax and conservative gate recognition are documented in the
release runbook; this module never executes YAML, shell, or network requests.
"""

from __future__ import annotations

import re

RULE_ID = "github-actions-pypi-unbound-release-source"
_JOB = re.compile(r"^  ([A-Za-z_][A-Za-z0-9_-]*):[^\n]*$", re.MULTILINE)
_STEP = re.compile(r"^      - [^\n]*", re.MULTILINE)
_PUBLISH = re.compile(
    r"^(?:      - |        )['\"]?uses['\"]?[ \t]*: *['\"]?pypa/gh-action-pypi-publish@[^\s'\"]+",
    re.MULTILINE | re.IGNORECASE,
)
_BUILD = re.compile(
    r"^(?:          |      - run: *|        run: *)python(?:3)? -m build(?:\s|$)",
    re.MULTILINE,
)


def _blocks(text, pattern):
    """Yield each matched header and its indentation-delimited source block."""
    matches = list(pattern.finditer(text))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        yield match, text[match.start():end]


def _gate(step):
    """Recognize only the reviewed unconditional, fail-closed source gate."""
    if re.search(r"^(?:      - |        )['\"]?(?:if|continue-on-error|shell)['\"]?[ \t]*:", step, re.MULTILINE):
        return False
    run = re.search(r"^        run: \|[-+]?\s*\n((?:          [^\n]*\n|\n)*)", step, re.MULTILINE)
    if not run:
        return False
    lines = [line[10:].strip() for line in run[1].splitlines() if line.strip()]
    # No preceding shell command/heredoc may donate inert gate-looking text.
    expected = [
        "set -euo pipefail",
        "git fetch --no-tags origin develop",
        'protected_sha="$(git rev-parse origin/develop)"',
        'if [ "$GITHUB_SHA" != "$protected_sha" ]; then',
    ]
    return (
        lines[:4] == expected
        and len(lines) >= 7
        and re.fullmatch(r'echo "::error::[^"]*"', lines[4]) is not None
        and lines[5:7] == ["exit 1", "fi"]
    )


def _bound_build(job):
    """Require a same-job gate before every recognized source build."""
    if re.search(r"^    ['\"]?continue-on-error['\"]?[ \t]*:", job, re.MULTILINE):
        return False
    bound = False
    checkout = False
    for _, step in _blocks(job, _STEP):
        if re.search(r"(?:^      - |^        )['\"]?uses['\"]?[ \t]*: *['\"]?actions/checkout@", step, re.MULTILINE):
            # Explicit alternate source, or a second checkout, invalidates proof.
            if re.search(
                r"^(?:          |        ['\"]?with['\"]?[ \t]*: *\{[^\n]*)['\"]?(?:ref|repository)['\"]?[ \t]*:",
                step,
                re.MULTILINE,
            ):
                return False
            checkout = True
            if bound:
                bound = False
        if checkout and _gate(step):
            bound = True
        if _BUILD.search(step) and not bound:
            return False
    return bound


def _needs(job):
    """Read scalar or inline-list dependencies from ordinary job metadata."""
    match = re.search(r"^    needs: *([^#\n]+)", job, re.MULTILINE)
    if not match:
        return []
    return [
        value.strip().strip("'\"")
        for value in match[1].strip().strip("[]").split(",")
    ]


class ReleaseSourcePattern:
    """Expose the scanner's finditer interface for one structural YAML rule."""

    def finditer(self, text):
        """Yield publisher action locations whose local source build is unbound."""
        # Trigger names inside comments or nested inputs are inert, not events.
        trigger_text = re.sub(r"^[ \t]*#[^\n]*(?:\n|$)", "", text, flags=re.MULTILINE)
        trigger = re.search(r"^['\"]?on['\"]?[ \t]*:([^\n]*(?:\n(?:[ \t]+[^\n]*|[ \t]*))*)", trigger_text, re.MULTILINE)
        if not trigger:
            return
        events = re.sub(r"#[^\n]*", "", trigger[0])
        if not (
            re.search(
                r"^(?:['\"]?on['\"]?[ \t]*:[ \t]*['\"]?workflow_dispatch['\"]?[ \t]*$|  ['\"]?workflow_dispatch['\"]?[ \t]*:)",
                events,
                re.MULTILINE,
            )
            or re.search(r"^  ['\"]?push['\"]?[ \t]*:\s*\n(?:    [^\n]*\n)*    ['\"]?tags['\"]?[ \t]*:", events, re.MULTILINE)
        ):
            return
        jobs_header = re.search(r"^jobs:\s*$", text, re.MULTILINE)
        if not jobs_header:
            return
        jobs = {
            match[1]: (match.start(), block)
            for match, block in _blocks(text[jobs_header.end():], _JOB)
        }
        for name, (offset, job) in jobs.items():
            publishers = list(_PUBLISH.finditer(job))
            if not publishers:
                continue
            pending, visited, builds = [name], set(), []
            while pending:
                dependency = pending.pop()
                if dependency in visited or dependency not in jobs:
                    continue
                visited.add(dependency)
                source = jobs[dependency][1]
                if _BUILD.search(source):
                    builds.append(source)
                pending.extend(_needs(source))
            if builds and not all(_bound_build(source) for source in builds):
                for publisher in publishers:
                    # Return real regex matches with absolute scanner offsets.
                    yield _PUBLISH.search(text, jobs_header.end() + offset + publisher.start())
