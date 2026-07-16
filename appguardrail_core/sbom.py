"""Generate a CycloneDX SBOM from common dependency manifests.

A software bill of materials is table-stakes for security due diligence — buyers
and auditors want the component inventory. This parses the manifests that
dominate AI-built apps (npm ``package.json``/``package-lock.json`` and Python
``requirements.txt``) into CycloneDX 1.5 JSON, with no third-party dependency
(stdlib only).

Versions come from the lockfile when present (resolved) and otherwise from the
manifest range (declared) — the component ``properties`` records which.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_RANGE_PREFIX = re.compile(r"^[\^~>=<\s]+")
# name==1.2.3 style; capture name and pinned version if present.
_REQ_LINE = re.compile(r"^([A-Za-z0-9._-]+)\s*(?:==\s*([A-Za-z0-9._+!-]+))?")
# poetry.lock: a package block is delimited by [[package]]; the package's own
# name/version are the first line-anchored ``name =``/``version =`` keys.
_POETRY_NAME = re.compile(r'^name\s*=\s*"([^"]+)"', re.MULTILINE)
_POETRY_VERSION = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)
# pnpm-lock.yaml package keys: "/name@version:" (v6+) and "/name/version:" (v5),
# scoped as "/@scope/name@version:" — trailing "(peer)" suffixes are ignored.
_PNPM_AT = re.compile(r"^\s+/(@?[^@\s/]+(?:/[^@\s/]+)?)@([^:@\s()]+)")
_PNPM_SLASH = re.compile(r"^\s+/(@[^/\s]+/[^/\s]+|[^/@\s]+)/([^:/\s()]+)")
# yarn.lock: a ``version "x"`` line inside an entry block.
_YARN_VERSION = re.compile(r'^\s+version\s+"?([^"\s]+)"?')


def _clean_version(value: str) -> str:
    return _RANGE_PREFIX.sub("", str(value or "")).strip()


def _component(
    name: str, version: str, ecosystem: str, resolved: bool
) -> dict[str, Any]:
    comp: dict[str, Any] = {
        "type": "library",
        "name": name,
        "purl": f"pkg:{ecosystem}/{name}" + (f"@{version}" if version else ""),
        "properties": [
            {
                "name": "appguardrail:version-source",
                "value": "resolved" if resolved else "declared",
            },
        ],
    }
    if version:
        comp["version"] = version
    return comp


def parse_package_lock(path: Path) -> list[dict[str, Any]]:
    """npm package-lock.json -> components with resolved versions."""
    data = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, dict[str, Any]] = {}
    # lockfile v2/v3: "packages" keyed by "node_modules/name"
    for key, meta in (data.get("packages") or {}).items():
        if not key or not isinstance(meta, dict):
            continue  # "" is the root project
        name = key.split("node_modules/")[-1]
        version = str(meta.get("version") or "")
        if name and version:
            out[name] = _component(name, version, "npm", resolved=True)
    # lockfile v1: "dependencies"
    for name, meta in (data.get("dependencies") or {}).items():
        if name not in out and isinstance(meta, dict) and meta.get("version"):
            out[name] = _component(name, str(meta["version"]), "npm", resolved=True)
    return list(out.values())


def parse_package_json(path: Path) -> list[dict[str, Any]]:
    """package.json -> components with declared version ranges."""
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, rng in (data.get(field) or {}).items():
            out.append(_component(name, _clean_version(rng), "npm", resolved=False))
    return out


def parse_requirements(path: Path) -> list[dict[str, Any]]:
    """requirements.txt -> components (pinned versions only get a version)."""
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://")):
            continue
        m = _REQ_LINE.match(line)
        if not m:
            continue
        out.append(
            _component(m.group(1), m.group(2) or "", "pypi", resolved=bool(m.group(2)))
        )
    return out


def parse_poetry_lock(path: Path) -> list[dict[str, Any]]:
    """poetry.lock -> components with resolved versions (hand-parsed TOML).

    Python 3.9 has no ``tomllib`` and we avoid third-party toml libs, so we
    scan ``[[package]]`` blocks for their first line-anchored ``name``/
    ``version`` keys (sub-tables like ``[package.dependencies]`` use the dep
    name as the key, never ``name =``/``version =`` at column 0).
    """
    text = path.read_text(encoding="utf-8")
    out: dict[str, dict[str, Any]] = {}
    # First chunk is the file preamble (before any [[package]]); skip it.
    for block in text.split("[[package]]")[1:]:
        nm = _POETRY_NAME.search(block)
        vm = _POETRY_VERSION.search(block)
        if nm and vm:
            name, version = nm.group(1), vm.group(1)
            out.setdefault(name, _component(name, version, "pypi", resolved=True))
    return list(out.values())


def parse_pnpm_lock(path: Path) -> list[dict[str, Any]]:
    """pnpm-lock.yaml -> components with resolved versions (hand-parsed).

    Package keys under ``packages:`` look like ``/name@version:`` (v6+) or
    ``/name/version:`` (v5), scoped as ``/@scope/name@...``. Peer-dependency
    suffixes such as ``(react@18.0.0)`` are excluded by the regexes.
    """
    out: dict[str, dict[str, Any]] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        m = _PNPM_AT.match(raw) or _PNPM_SLASH.match(raw)
        if not m:
            continue
        name, version = m.group(1), m.group(2)
        if name and version:
            out.setdefault(name, _component(name, version, "npm", resolved=True))
    return list(out.values())


def parse_yarn_lock(path: Path) -> list[dict[str, Any]]:
    """yarn.lock -> components with resolved versions (hand-parsed).

    Each entry starts with an unindented header of comma-separated
    ``"name@range"`` specs, followed by an indented ``version "1.2.3"`` line.
    The package name is the header spec with its trailing ``@range`` removed
    (scoped ``@scope/name`` is preserved).
    """
    out: dict[str, dict[str, Any]] = {}
    current: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace():
            current = None
            header = raw.rstrip()
            if not header.endswith(":"):
                continue
            first = header[:-1].split(",")[0].strip().strip('"')
            # Require an ``@range`` separator (beyond a leading scope ``@``) so
            # metadata blocks like ``__metadata:`` are ignored.
            if "@" not in first[1:]:
                continue
            name = first.rsplit("@", 1)[0]
            current = name or None
        elif current:
            vm = _YARN_VERSION.match(raw)
            if vm:
                out.setdefault(
                    current, _component(current, vm.group(1), "npm", resolved=True)
                )
                current = None
    return list(out.values())


def collect_components(base: Path) -> list[dict[str, Any]]:
    """Collect components, preferring lockfiles over manifests."""
    components: list[dict[str, Any]] = []
    # npm side: prefer a lockfile (resolved) over the manifest (declared);
    # among lockfiles npm > pnpm > yarn, then fall back to package.json.
    lock = base / "package-lock.json"
    pnpm = base / "pnpm-lock.yaml"
    yarn = base / "yarn.lock"
    pkg = base / "package.json"
    if lock.is_file():
        components += parse_package_lock(lock)
    elif pnpm.is_file():
        components += parse_pnpm_lock(pnpm)
    elif yarn.is_file():
        components += parse_yarn_lock(yarn)
    elif pkg.is_file():
        components += parse_package_json(pkg)
    # python side: requirements.txt plus poetry.lock (additive; de-duped below).
    req = base / "requirements.txt"
    if req.is_file():
        components += parse_requirements(req)
    poetry = base / "poetry.lock"
    if poetry.is_file():
        components += parse_poetry_lock(poetry)
    # de-dupe by (name, version)
    seen, unique = set(), []
    for c in components:
        key = (c["name"], c.get("version", ""))
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


def build_sbom(
    components: list[dict[str, Any]], app_name: str = "AppGuardrail scan target"
) -> dict[str, Any]:
    """Assemble a CycloneDX 1.5 document."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": app_name}},
        "components": components,
    }


if __name__ == "__main__":  # pragma: no cover - self-check
    import tempfile

    # Executable module self-checks; these assertions do not validate user input.
    with tempfile.TemporaryDirectory() as d:
        base = Path(d)
        (base / "package.json").write_text(
            '{"dependencies":{"next":"^14.1.0"},"devDependencies":{"jest":"29.0.0"}}'
        )
        (base / "requirements.txt").write_text(
            "flask==3.0.0\nrequests>=2\n# comment\n-e .\n"
        )
        comps = collect_components(base)
        names = {c["name"]: c for c in comps}
        assert names["next"]["version"] == "14.1.0"  # noqa: S101  # nosec B101
        assert names["next"]["purl"] == "pkg:npm/next@14.1.0"  # noqa: S101  # nosec B101
        assert names["flask"]["version"] == "3.0.0"  # noqa: S101  # nosec B101
        assert "version" not in names["requests"]  # noqa: S101  # nosec B101
        assert names["requests"]["purl"] == "pkg:pypi/requests"  # noqa: S101  # nosec B101
        sbom = build_sbom(comps, "demo")
        assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5"  # noqa: S101  # nosec B101
        assert len(sbom["components"]) == 4  # noqa: S101  # nosec B101
        print("sbom self-check OK")
