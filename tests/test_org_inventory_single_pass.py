"""Behavioral regression for incremental organization inventory consumption."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
import gc
from typing import Any
import weakref

from appguardrail_core.org_intelligence import build_org_inventory


class RepositoryRecord(Mapping[str, Any]):
    """Weak-referenceable repository record used by the regression source."""

    __slots__ = ("_values", "__weakref__")

    def __init__(self, values: dict[str, Any]) -> None:
        self._values = values

    def __getitem__(self, key: str) -> Any:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


class ReleasingRepositorySource:
    """Record whether a consumed item is released before source exhaustion."""

    first_record_released: bool | None = None

    def __iter__(self) -> Iterator[RepositoryRecord]:
        first_reference: weakref.ReferenceType[RepositoryRecord] | None = None
        for index, language in enumerate(("Python", "Rust", "TypeScript")):
            if index == 2:
                gc.collect()
                assert first_reference is not None
                self.first_record_released = first_reference() is None
            record = RepositoryRecord(
                {
                    "name": f"repo-{index}",
                    "isFork": index == 1,
                    "isPrivate": index == 2,
                    "primaryLanguage": {"name": language},
                    "defaultBranchRef": {"name": "main"},
                }
            )
            if index == 0:
                first_reference = weakref.ref(record)
            yield record
            del record


def test_consumed_repository_records_are_released_before_source_exhaustion() -> None:
    """Reject materialization or retention of already-consumed repository records."""
    source = ReleasingRepositorySource()

    inventory = build_org_inventory(source, active_repository_target=2)

    assert source.first_record_released is True
    assert inventory.total_repositories == 3
    assert inventory.nonfork_repositories == 2
    assert inventory.fork_repositories == 1
    assert inventory.private_repositories == 1
    assert inventory.unsupported_nonfork_languages == ()
