"""Focused contracts for Python shell-spawning command-injection findings."""

import pytest

from scanner.cli.appguardrail import _scan_file


EXPECTED_MESSAGE = (
    "Potential command injection detected: os.system/os.popen execute through a shell, "
    "or a subprocess API was invoked with shell=True. "
    "[OWASP A03:2021 - Injection]"
)


@pytest.mark.parametrize(
    ("filename", "source"),
    [
        ("os_system.py", "os.system('id')\n"),
        ("os_popen.py", "os.popen(command)\n"),
        ("subprocess_shell.py", "subprocess.call(command, shell=True)\n"),
    ],
)
def test_python_shell_spawning_apis_are_detected_independently(
    tmp_path, filename, source
):
    """Require each supported shell-spawning API shape to trigger on its own."""
    source_path = tmp_path / filename
    source_path.write_text(source, encoding="utf-8")

    matches = [
        finding
        for finding in _scan_file(source_path, tmp_path)
        if finding["rule_id"] == "python-command-injection"
    ]

    assert len(matches) == 1
    assert matches[0]["message"] == EXPECTED_MESSAGE


@pytest.mark.parametrize(
    "source",
    [
        "subprocess.call(['id'], shell=False)\n",
        "subprocess.run(['id'])\n",
    ],
)
def test_python_subprocess_without_shell_true_is_not_reported(tmp_path, source):
    """Keep ordinary non-shell subprocess execution outside this detector."""
    source_path = tmp_path / "safe_subprocess.py"
    source_path.write_text(source, encoding="utf-8")

    rule_ids = {
        finding["rule_id"] for finding in _scan_file(source_path, tmp_path)
    }

    assert "python-command-injection" not in rule_ids
