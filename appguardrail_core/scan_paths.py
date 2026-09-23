"""Build immutable scan-root path context for standalone and batch scanners.

The scanner repeatedly needs the same root classification and string boundary
while processing repository files. This module performs that work once, keeps
it immutable, and preserves the established single-file and directory-relative
path semantics without importing the CLI.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScanPathContext:
    """One immutable path-classification snapshot shared by a scan batch.

    Attributes:
        base_path: The caller-supplied scan root.
        resolved_base_path: The root used for relative display paths. Directory
            scans retain their supplied resolved root; single-file scans retain
            the historical current-working-directory root.
        resolved_base_path_str: Cached string form of ``resolved_base_path``.
        resolved_base_path_prefix: Cached root plus exactly one platform path
            separator, preventing prefix collisions such as ``repo`` and
            ``repository``.
        base_path_is_file: Whether the scan root represents one file.
    """

    base_path: Path
    resolved_base_path: Path
    resolved_base_path_str: str
    resolved_base_path_prefix: str
    base_path_is_file: bool

    def relative_candidate(self, file_path: Path) -> str:
        """Return the established pre-sanitization display candidate for a file.

        Children of a directory root become relative strings. A file equal to
        the resolved root becomes ``"."``. Paths outside a directory root stay
        absolute, while a single-file scan falls back to the filename.
        """
        file_path_str = str(file_path)
        if file_path_str == self.resolved_base_path_str:
            return "."
        if file_path_str.startswith(self.resolved_base_path_prefix):
            return file_path_str[len(self.resolved_base_path_prefix) :]
        if self.base_path_is_file:
            return file_path.name
        return file_path_str


def build_scan_path_context(
    base_path: Path,
    *,
    base_path_is_file: bool | None = None,
) -> ScanPathContext:
    """Classify one scan root and cache its reusable relative-path boundary.

    Batch callers should pass an already observed ``base_path_is_file`` value so
    this function performs no additional filesystem classification. Standalone
    callers may omit it and pay exactly one ``Path.is_file()`` call.

    Args:
        base_path: Scan root represented as ``pathlib.Path``.
        base_path_is_file: Optional previously computed file classification.

    Returns:
        An immutable context safe to share across every file in one scan.

    Raises:
        TypeError: If ``base_path`` is not ``Path`` or the optional
            classification is not a real Boolean.
    """
    if not isinstance(base_path, Path):
        raise TypeError("base_path must be a pathlib.Path")
    if base_path_is_file is not None and not isinstance(base_path_is_file, bool):
        raise TypeError("base_path_is_file must be a Boolean when provided")

    is_file = base_path.is_file() if base_path_is_file is None else base_path_is_file
    resolved_base_path = Path(".").resolve() if is_file else base_path
    resolved_base_path_str = str(resolved_base_path)
    resolved_base_path_prefix = (
        resolved_base_path_str
        if resolved_base_path_str.endswith(os.sep)
        else resolved_base_path_str + os.sep
    )
    return ScanPathContext(
        base_path=base_path,
        resolved_base_path=resolved_base_path,
        resolved_base_path_str=resolved_base_path_str,
        resolved_base_path_prefix=resolved_base_path_prefix,
        base_path_is_file=is_file,
    )


__all__ = ["ScanPathContext", "build_scan_path_context"]
