"""Deterministic, provably-safe auto-fixes for a subset of findings.

Most security fixes change behavior and must NOT be applied blindly (moving a
secret to env, flipping TLS verification, etc. can break a build) — those stay
as fix-pack prompts for a human/AI to apply. This module only performs edits
that are purely additive and semantics-preserving, so `appguardrail fix` is
safe to run. New safe transforms plug into ``SAFE_FIXES``.
"""

from __future__ import annotations

import re
from typing import Callable

# One opening <a ...> tag (no embedded '>').
_A_TAG = re.compile(r"<a\b[^>]*>", re.IGNORECASE)
_HAS_EXTERNAL_BLANK = re.compile(
    r"target\s*=\s*[\"']_blank[\"']", re.IGNORECASE
)
_HAS_EXTERNAL_HREF = re.compile(r"href\s*=\s*[\"']https?://", re.IGNORECASE)
_HAS_REL_SAFE = re.compile(
    r"rel\s*=\s*[\"'][^\"']*(?:noopener|noreferrer)", re.IGNORECASE
)


def _fix_target_blank_noopener(text: str) -> "tuple[str, int]":
    """Add rel="noopener noreferrer" to external target=_blank links missing it.

    Purely additive: inserts a rel attribute; never removes or alters others.
    """
    count = 0

    def repl(match: "re.Match[str]") -> str:
        nonlocal count
        tag = match.group(0)
        if (
            _HAS_EXTERNAL_BLANK.search(tag)
            and _HAS_EXTERNAL_HREF.search(tag)
            and not _HAS_REL_SAFE.search(tag)
        ):
            count += 1
            return re.sub(r"<a\b", '<a rel="noopener noreferrer"', tag, count=1, flags=re.IGNORECASE)
        return tag

    return _A_TAG.sub(repl, text), count


# rule_id -> (file extensions it applies to, transform)
SAFE_FIXES: "dict[str, tuple[tuple[str, ...], Callable[[str], tuple[str, int]]]]" = {
    "html-target-blank-without-noopener": ((".html", ".htm"), _fix_target_blank_noopener),
}


def fixable_extensions() -> "set[str]":
    exts = set()
    for extensions, _ in SAFE_FIXES.values():
        exts.update(extensions)
    return exts


def apply_safe_fixes(text: str, ext: str) -> "tuple[str, int]":
    """Apply every safe transform whose extension matches. Returns (text, fixes)."""
    total = 0
    for extensions, transform in SAFE_FIXES.values():
        if ext.lower() in extensions:
            text, count = transform(text)
            total += count
    return text, total


if __name__ == "__main__":  # pragma: no cover - self-check
    src = '<a href="https://x.com" target="_blank">x</a>\n<a href="/local" target="_blank">l</a>\n<a href="https://y.com" target="_blank" rel="noopener">y</a>'
    out, n = apply_safe_fixes(src, ".html")
    assert n == 1, n  # only the external, rel-less one is fixed
    assert 'rel="noopener noreferrer"' in out
    assert out.count("rel=") == 2  # original rel preserved, one added
    # idempotent: running again fixes nothing
    _, n2 = apply_safe_fixes(out, ".html")
    assert n2 == 0
    # non-matching extension is a no-op
    _, n3 = apply_safe_fixes(src, ".py")
    assert n3 == 0
    print("autofix self-check OK")
