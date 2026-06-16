import runpy
from unittest.mock import patch, MagicMock

def test_error_path(capsys, monkeypatch):
    monkeypatch.setattr("sys.argv", ["pr_review_merge_scheduler.py", "--repo", "owner/repo"])

    with patch("subprocess.run") as mock_run:
        mock_process = MagicMock()
        mock_process.returncode = 1
        mock_process.stderr = "fake error message"
        mock_run.return_value = mock_process

        try:
            runpy.run_path("scripts/ci/pr_review_merge_scheduler.py", run_name="__main__")
        except SystemExit as exc:
            assert exc.code == 1
        else:
            assert False, "SystemExit not raised"

        captured = capsys.readouterr()
        assert "Command failed" in captured.err
        assert "fake error message" in captured.err
