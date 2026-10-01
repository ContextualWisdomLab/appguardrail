"""Regression tests for external-reference link accessibility."""

import re
from html.parser import HTMLParser

from scanner.cli.appguardrail import dashboard_index_path


class _LinkAttributeParser(HTMLParser):
    """Collect attributes from dashboard link markup."""

    def __init__(self) -> None:
        """Initialize an empty link-attribute collection."""
        super().__init__()
        self.links: list[dict[str, str | None]] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        """Record anchor attributes and ignore every other element."""
        if tag == "a":
            self.links.append(dict(attrs))


def test_dashboard_external_links_announce_new_tab_behavior() -> None:
    """A screen-reader user must know that a reference opens a new tab."""
    html = dashboard_index_path().read_text(encoding="utf-8")
    detail_markup = re.search(
        r"const refs = \(f\.references\|\|\[\]\)\.map\(r=>`(.*?)`\)\.join\('<br>'\);",
        html,
        flags=re.DOTALL,
    )
    assert detail_markup is not None

    parser = _LinkAttributeParser()
    parser.feed(detail_markup.group(1))

    assert any(
        attributes.get("target") == "_blank"
        and attributes.get("rel") == "noopener"
        and attributes.get("aria-label") == "${esc(r)} (opens in a new tab)"
        for attributes in parser.links
    )
