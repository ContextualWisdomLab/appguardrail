"""Tests for the official Docker image definition."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_contract():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert 'ENTRYPOINT ["appguardrail"]' in text
    assert "pip install" in text
    assert "USER scanner" in text  # non-root
    assert "python:3.12-slim" in text


def test_dockerignore_excludes_noise():
    text = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    for entry in (".git", "tests", "__pycache__"):
        assert entry in text
