"""Refine and apply the OpenCode hardening after filesystem-edge review."""

from __future__ import annotations

from scripts.ci import harden_opencode_commercial_loop_once as base


def _replace_once(text: str, old: str, new: str, label: str) -> str:
    """Replace one exact generated contract or stop before writing output."""
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    """Patch the generated module/tests and invoke the original bounded writer."""
    base.WORKFLOW = _replace_once(
        base.WORKFLOW,
        "ref: ${{ github.event.repository.default_branch }}",
        "ref: ${{ github.sha }}",
        "exact checkout",
    )
    base.AGENT_TESTS = _replace_once(
        base.AGENT_TESTS,
        'assert "ref: ${{ github.event.repository.default_branch }}" in workflow',
        'assert "ref: ${{ github.sha }}" in workflow',
        "checkout assertion",
    )
    base.CONTRACT_MODULE = _replace_once(
        base.CONTRACT_MODULE,
        "import re\nfrom pathlib import Path",
        "import re\nimport tempfile\nfrom pathlib import Path",
        "tempfile import",
    )
    base.CONTRACT_MODULE = _replace_once(
        base.CONTRACT_MODULE,
        '''def _output_path(value: str) -> Path:
    """Return a repository-local output path without traversal or symlinks."""
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("output must be a repository-relative path")
    root = Path.cwd().resolve()
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root):
        raise ValueError("output must stay inside the repository")
    if resolved.exists() and resolved.is_symlink():
        raise ValueError("output must not be a symlink")
    return resolved


def write_contract(contract: dict[str, Any], output: str) -> Path:
    """Atomically write one deterministic read-only JSON contract."""
    destination = _output_path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    try:
        temporary.write_text(
            json.dumps(contract, indent=2, sort_keys=True) + "\\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        temporary.replace(destination)
        destination.chmod(0o444)
    finally:
        if temporary.exists():
            temporary.unlink()
    return destination
''',
        '''def _output_path(value: str) -> Path:
    """Return a repository-local output path without traversal or symlinks."""
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("output must be a repository-relative path")
    root = Path.cwd().resolve()
    candidate = root / path
    if candidate.is_symlink():
        raise ValueError("output must not be a symlink")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError("output must stay inside the repository")
    return resolved


def write_contract(contract: dict[str, Any], output: str) -> Path:
    """Atomically write one deterministic read-only JSON contract."""
    destination = _output_path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=destination.parent,
        prefix=destination.name + ".",
        suffix=".tmp",
        delete=False,
    ) as handle:
        handle.write(json.dumps(contract, indent=2, sort_keys=True) + "\\n")
        temporary = Path(handle.name)
    try:
        temporary.chmod(0o600)
        os.replace(temporary, destination)
        destination.chmod(0o444)
    finally:
        temporary.unlink(missing_ok=True)
    return destination
''',
        "filesystem-safe contract writer",
    )
    base.CONTRACT_TESTS = _replace_once(
        base.CONTRACT_TESTS,
        '''def test_write_contract_rejects_escape_and_symlink(tmp_path, monkeypatch) -> None:
    """The output cannot leave the checkout or replace a symlink target."""
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match="repository-relative"):
        contract.write_contract({}, "../outside.json")
    with pytest.raises(ValueError, match="repository-relative"):
        contract.write_contract({}, str(tmp_path / "absolute.json"))

    target = tmp_path / "target.json"
    target.write_text("safe", encoding="utf-8")
    link = tmp_path / "contract.json"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable")
    with pytest.raises(ValueError, match="symlink"):
        contract.write_contract({}, "contract.json")


def test_parse_args_returns_stable_namespace() -> None:
''',
        '''def test_write_contract_rejects_escape_and_symlink(tmp_path, monkeypatch) -> None:
    """The output cannot leave the checkout or replace a symlink target."""
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match="repository-relative"):
        contract.write_contract({}, "../outside.json")
    with pytest.raises(ValueError, match="repository-relative"):
        contract.write_contract({}, str(tmp_path / "absolute.json"))

    target = tmp_path / "target.json"
    target.write_text("safe", encoding="utf-8")
    link = tmp_path / "contract.json"
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    parent_link = tmp_path / "linked-directory"
    try:
        link.symlink_to(target)
        parent_link.symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable")
    with pytest.raises(ValueError, match="symlink"):
        contract.write_contract({}, "contract.json")
    with pytest.raises(ValueError, match="stay inside"):
        contract.write_contract({}, "linked-directory/contract.json")


def test_write_contract_cleans_temporary_file_on_replace_failure(
    tmp_path, monkeypatch
) -> None:
    """An interrupted atomic replacement leaves neither output nor temp data."""
    monkeypatch.chdir(tmp_path)

    def fail_replace(_source, _destination):
        raise OSError("replace unavailable")

    monkeypatch.setattr(contract.os, "replace", fail_replace)
    with pytest.raises(OSError, match="replace unavailable"):
        contract.write_contract({"safe": True}, "contract.json")

    assert not (tmp_path / "contract.json").exists()
    assert list(tmp_path.glob("contract.json.*.tmp")) == []


def test_parse_args_returns_stable_namespace() -> None:
''',
        "filesystem regression tests",
    )
    base.main()


if __name__ == "__main__":
    main()
