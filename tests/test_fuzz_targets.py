"""Smoke tests for fuzz targets so they stay importable in CI."""

from fuzz.fuzz_cli_inputs import TestOneInput


def test_cli_input_fuzz_target_accepts_representative_seeds():
    """Run representative seeds through the CLI helper fuzz target."""
    for seed in (
        b"",
        b"scanner/cli/appguardrail.py\x00**/*.py",
        b".github\\workflows\\security-process.yml\x00.github/**",
        b"\x1b[31mhidden",
    ):
        TestOneInput(seed)
