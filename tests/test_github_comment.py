"""Tests for the sticky PR comment (appguardrail_core.github_comment)."""

import json

from appguardrail_core import github_comment as gc

FINDINGS = [
    {"severity": "CRITICAL", "rule_id": "secret", "file": "a.ts", "line": 3,
     "message": "hardcoded", "context": "app-code"},
    {"severity": "INFO", "rule_id": "note", "file": "b.md", "line": 1,
     "message": "fyi", "context": "doc"},
]


def test_build_comment_has_marker_and_summary():
    body = gc.build_comment(FINDINGS)
    assert body.startswith(gc.MARKER)
    assert "AppGuardrail" in body and "CRITICAL" in body


def test_pr_number_from_ref():
    assert gc._pr_number(None, "refs/pull/17/merge") == 17
    assert gc._pr_number(None, "refs/heads/main") is None
    assert gc._pr_number(None, None) is None


def test_pr_number_from_event(tmp_path):
    ev = tmp_path / "event.json"
    ev.write_text(json.dumps({"pull_request": {"number": 99}}), encoding="utf-8")
    assert gc._pr_number(str(ev), None) == 99


def test_pr_number_falls_back_to_ref_for_bad_event_number(tmp_path):
    ev = tmp_path / "event.json"
    ev.write_text(json.dumps({"pull_request": {"number": "bad"}}), encoding="utf-8")
    assert gc._pr_number(str(ev), "refs/pull/17/merge") == 17


def test_post_skips_without_token(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    assert gc.post(FINDINGS).startswith("skipped")


def test_post_skips_when_not_pr(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    assert gc.post(FINDINGS).startswith("skipped")


def test_post_creates_then_updates(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.setenv("GITHUB_REF", "refs/pull/5/merge")
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)

    calls = []
    state = {"comments": []}

    def fake_request(method, url, token, body=None):
        calls.append((method, url))
        if method == "GET":
            return state["comments"]
        if method == "POST":
            state["comments"].append({"id": 1, "body": body["body"]})
            return {"id": 1}
        if method == "PATCH":
            state["comments"][0]["body"] = body["body"]
            return {"id": 1}
        raise AssertionError(f"unexpected request method: {method}")

    monkeypatch.setattr(gc, "_request", fake_request)

    r1 = gc.post(FINDINGS)
    assert "created" in r1 and "#5" in r1
    r2 = gc.post(FINDINGS)  # second run finds the sticky comment -> update
    assert "updated" in r2
    assert any(m == "PATCH" for m, _ in calls)


def test_load_accepts_wrapped_and_bare(tmp_path):
    wrapped = tmp_path / "w.json"
    wrapped.write_text(json.dumps({"schema": "x", "findings": FINDINGS}), encoding="utf-8")
    assert gc._load(str(wrapped)) == FINDINGS
    bare = tmp_path / "b.json"
    bare.write_text(json.dumps(FINDINGS), encoding="utf-8")
    assert gc._load(str(bare)) == FINDINGS
