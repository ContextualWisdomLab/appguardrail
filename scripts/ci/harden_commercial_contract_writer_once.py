"""Harden runtime contract serialization and replacement failure semantics."""

from __future__ import annotations

from pathlib import Path


def _ensure_finalized() -> None:
    """Run the latest-state finalizer if an earlier queued pass has not done so."""
    if Path("scripts/ci/render_commercial_gap_contract.py").exists():
        return
    from scripts.ci import finalize_opencode_commercial_loop_once as finalizer

    finalizer.main()


def _replace_once(text: str, old: str, new: str, label: str) -> str:
    """Replace one exact reviewed fragment or fail before writing output."""
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    """Make every temporary-file path clean up and seal before publication."""
    _ensure_finalized()
    module_path = Path("scripts/ci/render_commercial_gap_contract.py")
    module = module_path.read_text(encoding="utf-8")
    module = module.replace(
        """    if not isinstance(issue_number, int) or isinstance(issue_number, bool) or issue_number <= 0:
        raise ValueError("issue_number must be a positive integer")
""",
        """    if (
        not isinstance(issue_number, int)
        or isinstance(issue_number, bool)
        or issue_number <= 0
    ):
        raise ValueError("issue_number must be a positive integer")
""",
    )
    module = _replace_once(
        module,
        '''def write_contract(contract: dict[str, Any], output: str) -> Path:
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
        '''def write_contract(contract: dict[str, Any], output: str) -> Path:
    """Atomically publish one deterministic contract already sealed read-only."""
    destination = _output_path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=destination.name + ".",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(json.dumps(contract, indent=2, sort_keys=True) + "\\n")
        temporary.chmod(0o444)
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination
''',
        "atomic contract writer",
    )
    module_path.write_text(module, encoding="utf-8")

    tests_path = Path("tests/test_render_commercial_gap_contract.py")
    tests = tests_path.read_text(encoding="utf-8")
    insertion = '''

def test_write_contract_cleans_temporary_file_on_serialization_failure(
    tmp_path, monkeypatch
) -> None:
    """Unserializable data leaves no output or temporary contract material."""
    monkeypatch.chdir(tmp_path)

    with pytest.raises(TypeError):
        contract.write_contract({"invalid": object()}, "contract.json")

    assert not (tmp_path / "contract.json").exists()
    assert list(tmp_path.glob("contract.json.*.tmp")) == []
'''
    marker = "\ndef test_parse_args_returns_stable_namespace() -> None:\n"
    if "test_write_contract_cleans_temporary_file_on_serialization_failure" not in tests:
        if tests.count(marker) != 1:
            raise SystemExit("contract test insertion point changed")
        tests = tests.replace(marker, insertion + marker, 1)
    tests_path.write_text(tests, encoding="utf-8")


if __name__ == "__main__":
    main()
