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


def _clean_version(value: str) -> str:
    return _RANGE_PREFIX.sub("", str(value or "")).strip()


def _component(name: str, version: str, ecosystem: str, resolved: bool) -> dict[str, Any]:
    comp: dict[str, Any] = {
        "type": "library",
        "name": name,
        "purl": f"pkg:{ecosystem}/{name}" + (f"@{version}" if version else ""),
        "properties": [
            {"name": "appguardrail:version-source", "value": "resolved" if resolved else "declared"},
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
        out.append(_component(m.group(1), m.group(2) or "", "pypi", resolved=bool(m.group(2))))
    return out


def collect_components(base: Path) -> list[dict[str, Any]]:
    """Collect components, preferring lockfiles over manifests."""
    components: list[dict[str, Any]] = []
    lock = base / "package-lock.json"
    pkg = base / "package.json"
    if lock.is_file():
        components += parse_package_lock(lock)
    elif pkg.is_file():
        components += parse_package_json(pkg)
    req = base / "requirements.txt"
    if req.is_file():
        components += parse_requirements(req)
    # de-dupe by (name, version)
    seen, unique = set(), []
    for c in components:
        key = (c["name"], c.get("version", ""))
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


def build_sbom(components: list[dict[str, Any]], app_name: str = "AppGuardrail scan target") -> dict[str, Any]:
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

    with tempfile.TemporaryDirectory() as d:
        base = Path(d)
        (base / "package.json").write_text('{"dependencies":{"next":"^14.1.0"},"devDependencies":{"jest":"29.0.0"}}')
        (base / "requirements.txt").write_text("flask==3.0.0\nrequests>=2\n# comment\n-e .\n")
        comps = collect_components(base)
        names = {c["name"]: c for c in comps}
        assert names["next"]["version"] == "14.1.0"  # ^ stripped
        assert names["next"]["purl"] == "pkg:npm/next@14.1.0"
        assert names["flask"]["version"] == "3.0.0"
        assert "version" not in names["requests"]  # unpinned -> no version
        assert names["requests"]["purl"] == "pkg:pypi/requests"
        sbom = build_sbom(comps, "demo")
        assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5"
        assert len(sbom["components"]) == 4
        print("sbom self-check OK")
