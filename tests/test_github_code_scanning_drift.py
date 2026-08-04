"""Tests for GitHub Code Scanning analysis drift detection."""

from __future__ import annotations

from typing import Any
import pytest
import urllib.error
import urllib.request

from appguardrail_core.issueops import (
    CodeScanningAPIError,
    CodeScanningPermissionError,
    normalize_category,
    detect_code_scanning_drift,
    fetch_code_scanning_analyses,
    has_local_sarif_trigger_finding,
    diagnosis,
)


class DummyResponse:
    """Mock for urllib responses to satisfy context manager and read/close methods."""

    def __init__(self, content: bytes, status: int = 200, headers: dict[str, str] | None = None):
        self.content = content
        self.status = status
        self.headers = headers or {"content-type": "application/json"}

    def read(self) -> bytes:
        return self.content

    def close(self) -> None:
        pass

    def __enter__(self) -> DummyResponse:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        return False


def test_normalize_category():
    """Verify that categories are normalized stably."""
    assert normalize_category("/language:python") == "language:python"
    assert normalize_category("  /language:javascript/  ") == "language:javascript"
    assert normalize_category("") == ""
    assert normalize_category(None) == ""


def test_detect_code_scanning_drift_stable():
    """Verify drift detection logic with stable category matching."""
    base = [
        {"tool": {"name": "CodeQL"}, "category": "/language:python"},
        {"tool": {"name": "Trivy"}, "category": ""},
    ]
    # No drift: category is normalized, tool names match
    head = [
        {"tool": {"name": "CodeQL"}, "category": "language:python"},
        {"tool": {"name": "Trivy"}, "category": None},
    ]
    result = detect_code_scanning_drift(base, head)
    assert not result["drifted"]
    assert len(result["missing"]) == 0
    assert len(result["base_coverage"]) == 2
    assert len(result["head_coverage"]) == 2


def test_detect_code_scanning_drift_with_missing_head():
    """Verify drift detection when a tool/category pair is missing on head."""
    base = [
        {"tool": {"name": "CodeQL"}, "category": "/language:python"},
        {"tool": {"name": "Trivy"}, "category": "/security:secret"},
    ]
    head = [
        {"tool": {"name": "CodeQL"}, "category": "/language:python"},
    ]
    result = detect_code_scanning_drift(base, head)
    assert result["drifted"]
    assert result["missing"] == [{"tool_name": "Trivy", "category": "security:secret"}]


def test_detect_code_scanning_drift_absent_head():
    """Verify drift detection when head has no analyses at all."""
    base = [
        {"tool": {"name": "CodeQL"}, "category": "/language:python"},
    ]
    head: list[dict[str, Any]] = []
    result = detect_code_scanning_drift(base, head)
    assert result["drifted"]
    assert result["missing"] == [{"tool_name": "CodeQL", "category": "language:python"}]


def test_has_local_sarif_trigger_finding():
    """Verify detection of local workflows uploading SARIF but lacking PR triggers."""
    # Lacks PR trigger
    content1 = """
name: Upload SARIF
on:
  push:
    branches: [main]
jobs:
  upload:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/upload-sarif@v3
    """
    assert has_local_sarif_trigger_finding([content1])

    # Has PR trigger
    content2 = """
name: Upload SARIF
on:
  pull_request:
jobs:
  upload:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/upload-sarif@v3
    """
    assert not has_local_sarif_trigger_finding([content2])

    # Suppressed by central required workflow marker
    content3 = """
# appguardrail: central-code-scanning
name: Upload SARIF
on:
  push:
jobs:
  upload:
    runs-on: ubuntu-latest
    steps:
      - uses: github/codeql-action/upload-sarif@v3
    """
    assert not has_local_sarif_trigger_finding([content3])


def test_fetch_code_scanning_analyses_success(monkeypatch):
    """Verify fetching and paginating Code Scanning analyses successfully."""
    calls = []

    def mock_open(request, timeout=None):
        calls.append(request.full_url)
        # First page has 100 items, second page has 2 items
        if "page=1" in request.full_url and "per_page=100&page=1" in request.full_url:
            payload = b"[" + b",".join(b'{"id": 1, "tool": {"name": "CodeQL"}, "category": "py"}' for _ in range(100)) + b"]"
        else:
            payload = b'[{"id": 2, "tool": {"name": "CodeQL"}, "category": "py"}]'
        return DummyResponse(payload)

    original_build_opener = urllib.request.build_opener
    def mock_build_opener(*handlers):
        opener = original_build_opener(*handlers)
        monkeypatch.setattr(opener, "open", mock_open)
        return opener

    monkeypatch.setattr(urllib.request, "build_opener", mock_build_opener)

    analyses = fetch_code_scanning_analyses("fake-token", "owner/repo", "refs/heads/main")
    assert len(analyses) == 101
    assert any("page=1" in url for url in calls)
    assert any("page=2" in url for url in calls)


def test_fetch_code_scanning_analyses_partial_permissions(monkeypatch):
    """Verify that 403 or 404 results in CodeScanningPermissionError."""
    def mock_open(request, timeout=None):
        fp = DummyResponse(b'{"message": "Not Found"}', status=404)
        raise urllib.error.HTTPError(
            request.full_url, 404, "Not Found", request.headers, fp
        )

    original_build_opener = urllib.request.build_opener
    def mock_build_opener(*handlers):
        opener = original_build_opener(*handlers)
        monkeypatch.setattr(opener, "open", mock_open)
        return opener

    monkeypatch.setattr(urllib.request, "build_opener", mock_build_opener)

    with pytest.raises(CodeScanningPermissionError):
        fetch_code_scanning_analyses("fake-token", "owner/repo", "refs/heads/main")


def test_fetch_code_scanning_analyses_api_failure(monkeypatch):
    """Verify that other HTTP errors or failures result in CodeScanningAPIError."""
    def mock_open(request, timeout=None):
        fp = DummyResponse(b'{"message": "Internal Server Error"}', status=500)
        raise urllib.error.HTTPError(
            request.full_url, 500, "Internal Server Error", request.headers, fp
        )

    original_build_opener = urllib.request.build_opener
    def mock_build_opener(*handlers):
        opener = original_build_opener(*handlers)
        monkeypatch.setattr(opener, "open", mock_open)
        return opener

    monkeypatch.setattr(urllib.request, "build_opener", mock_build_opener)

    with pytest.raises(CodeScanningAPIError):
        fetch_code_scanning_analyses("fake-token", "owner/repo", "refs/heads/main")


def test_drift_diagnosis():
    """Verify diagnosis content for Code Scanning Drift findings."""
    finding = {
        "workflow": "GitHub Code Scanning Drift",
        "job_name": "drift-detector",
        "conclusion": "failure",
    }
    diag = diagnosis(finding)
    assert "GitHub Code Scanning configuration has drifted" in diag
    assert "Verify that all static analysis tools" in diag


def test_fetch_code_scanning_analyses_invalid_url():
    """Verify that fetch_code_scanning_analyses raises ValueError for invalid API URL."""
    with pytest.raises(ValueError, match="GitHub API root must be"):
        fetch_code_scanning_analyses("fake-token", "owner/repo", "refs/heads/main", "https://attacker.invalid")
