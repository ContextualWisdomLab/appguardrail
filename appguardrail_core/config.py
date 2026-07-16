"""Optional project configuration for AppGuardrail scans.

A repo may ship a ``.appguardrail.json`` to tune the deploy gate without CLI
flags — the single artifact a team commits to configure CI. JSON (not YAML) so
the scanner stays dependency-free (``pyproject`` dependencies = []).

Supported keys::

    {
      "fail_on": "HIGH",              // min severity that fails the gate
      "exclude_rules": ["rule-id"]    // rule ids to drop from the gate
    }
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .findings import SEVERITIES, severities_at_or_above

CONFIG_NAME = ".appguardrail.json"


def find_config(search_dirs: "list[Path]") -> "Path | None":
    """Return the first existing ``.appguardrail.json`` in ``search_dirs``."""
    seen = set()
    for directory in search_dirs:
        path = Path(directory) / CONFIG_NAME
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        if path.is_file():
            return path
    return None


def load_config(search_dirs: "list[Path]") -> dict[str, Any]:
    """Load and validate config from the first match, or {} if none.

    Raises RuntimeError on malformed JSON or invalid values so scans fail loud
    rather than silently ignoring a broken gate config.
    """
    path = find_config(search_dirs)
    if path is None:
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Invalid {CONFIG_NAME} at {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"{CONFIG_NAME} at {path} must be a JSON object.")

    config: dict[str, Any] = {"_path": str(path)}

    fail_on = data.get("fail_on")
    if fail_on is not None:
        fail_on = str(fail_on).upper()
        if fail_on not in SEVERITIES:
            raise RuntimeError(
                f"{CONFIG_NAME}: fail_on must be one of {list(SEVERITIES)}, got {fail_on!r}"
            )
        config["fail_on"] = fail_on
        config["blocking_severities"] = severities_at_or_above(fail_on)

    exclude = data.get("exclude_rules") or []
    if not isinstance(exclude, list):
        raise RuntimeError(f"{CONFIG_NAME}: exclude_rules must be a list of rule ids.")
    config["exclude_rules"] = {str(rule_id) for rule_id in exclude}

    return config


if __name__ == "__main__":  # pragma: no cover - self-check
    import tempfile

    # Executable module self-checks; these assertions do not validate user input.
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / CONFIG_NAME).write_text(
            '{"fail_on": "WARNING", "exclude_rules": ["noisy-rule"]}'
        )
        cfg = load_config([Path(d)])
        assert cfg["fail_on"] == "WARNING"  # noqa: S101  # nosec B101
        assert cfg["blocking_severities"] == {  # noqa: S101  # nosec B101
            "CRITICAL",
            "HIGH",
            "WARNING",
        }
        assert cfg["exclude_rules"] == {  # noqa: S101  # nosec B101
            "noisy-rule"
        }
        assert load_config([Path(d) / "nope"]) == {}  # noqa: S101  # nosec B101
    print("config self-check OK")
