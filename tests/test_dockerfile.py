"""Tests for the official Docker image definition."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_contract():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert 'ENTRYPOINT ["python", "-m", "scanner.cli.appguardrail"]' in text
    assert "pip install" not in text
    assert "USER scanner" in text  # non-root
    assert (
        "python:3.12-slim"
        "@sha256:423ed6ab25b1921a477529254bfeeabf5855151dc2c3141699a1bfc852199fbf"
    ) in text
    assert "ENV PYTHONPATH=/app" in text
    assert "HEALTHCHECK" in text


def test_dockerignore_excludes_noise():
    text = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    for entry in (".git", "tests", "__pycache__"):
        assert entry in text
