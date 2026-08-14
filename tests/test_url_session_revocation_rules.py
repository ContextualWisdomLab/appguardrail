"""Source-authoritative regressions for URL-session revocation bypasses."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "javascript-url-session-jwt-revocation-bypass"
_SOURCE_REPOSITORY = "ContextualWisdomLab/scopeweave"
_COLLECTOR_ISSUE = 775
_SOURCE_PR = 397
_HISTORICAL_VULNERABLE_HEAD_SHA = "a756b7e3cf486cba0930c1a482c6a30e0df958f5"
_HISTORICAL_VULNERABLE_BLOB_SHA = "926d528d17b7ae39ab89001657a21f7ef30af743"
_CURRENT_PROTECTED_HEAD_SHA = "b88e66e81e9701404d29a0f5de4f58573ceee14f"
_CURRENT_PROTECTED_BLOB_SHA = "450be87886a9668fbe39b427aaeb08fc3438dc5d"
_FIXED_CANDIDATE_HEAD_SHA = "5ed7fa125bcf63df4bb548d8bc244ac4ddf0054c"
_FIXED_CANDIDATE_BLOB_SHA = "b5ea69b272f571c1fd3b677c07b636f5f7ca610e"

_CALENDAR_VULNERABLE = """
app.get('/api/projects/:id/calendar.ics', (c) => {
  const header = c.req.header('authorization') || '';
  const raw = header.startsWith('Bearer ') ? header.slice(7) : (c.req.query('token') || '');
  let uid;
  if (raw.startsWith('swk_')) {
    const row = db.prepare('SELECT user_id FROM api_tokens WHERE token_hash = ?').get(hashApiToken(raw));
    if (!row) return c.json({ error: 'unauthorized' }, 401);
    uid = row.user_id;
  } else {
    try { uid = verifyToken(raw).sub; } catch { return c.json({ error: 'unauthorized' }, 401); }
  }
  const p = projectAccess(uid, c.req.param('id'));
  return c.json({ id: p.id });
});
"""

_STREAM_VULNERABLE = """
app.get('/api/projects/:id/stream', (c) => {
  const header = c.req.header('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : (c.req.query('token') || '');
  let user;
  try { user = verifyToken(token); } catch { return c.json({ error: 'unauthorized' }, 401); }
  const id = c.req.param('id');
  if (!projectAccess(user.sub, id)) return c.json({ error: 'not found' }, 404);
  return c.body(null, 200);
});
"""

_FIXED_CANDIDATE = """
function verifySessionJwt(token) {
  const payload = verifyToken(token);
  const user = db.prepare('SELECT token_version FROM users WHERE id = ?').get(payload.sub);
  if (!user || (payload.tv || 0) !== user.token_version) throw new Error('revoked session');
  return payload;
}

app.get('/api/projects/:id/calendar.ics', (c) => {
  const header = c.req.header('authorization') || '';
  const raw = header.startsWith('Bearer ') ? header.slice(7) : (c.req.query('token') || '');
  let uid;
  if (raw.startsWith('swk_')) {
    const row = db.prepare('SELECT user_id FROM api_tokens WHERE token_hash = ?').get(hashApiToken(raw));
    if (!row) return c.json({ error: 'unauthorized' }, 401);
    uid = row.user_id;
  } else {
    try { uid = verifySessionJwt(raw).sub; }
    catch { return c.json({ error: 'unauthorized' }, 401); }
  }
  return c.json({ ok: true });
});

app.get('/api/projects/:id/stream', (c) => {
  const header = c.req.header('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : (c.req.query('token') || '');
  let user;
  try { user = verifySessionJwt(token); }
  catch { return c.json({ error: 'unauthorized' }, 401); }
  return c.json({ ok: true });
});
"""

_EXPLICIT_INLINE_REVOCATION = """
app.get('/api/projects/:id/attachments/:aid/view', (c) => {
  const raw = c.req.query('token') || '';
  let uid;
  try {
    const payload = verifyToken(raw);
    const user = db.prepare('SELECT token_version FROM users WHERE id = ?').get(payload.sub);
    if (!user || (payload.tv || 0) !== user.token_version) return c.json({ error: 'unauthorized' }, 401);
    uid = payload.sub;
  } catch { return c.json({ error: 'unauthorized' }, 401); }
  return c.json({ uid });
});
"""

_BEARER_ONLY_DIRECT_VERIFY = """
app.get('/api/profile', (c) => {
  const header = c.req.header('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const user = verifyToken(token);
  return c.json({ id: user.sub });
});
"""


def _rule() -> dict:
    """Return the packaged URL-session revocation detector."""
    matches = [rule for rule in SCAN_RULES if rule["id"] == _RULE_ID]
    assert len(matches) == 1, f"expected one loaded rule for {_RULE_ID}"
    return matches[0]


def _scan(source: str, tmp_path: Path) -> list[dict]:
    """Run the production scanner over one JavaScript replay."""
    source_file = tmp_path / "app.mjs"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_source_provenance_is_explicit() -> None:
    """Pin historical/current vulnerable source and the reviewed fixed candidate."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/scopeweave"
    assert _COLLECTOR_ISSUE == 775
    assert _SOURCE_PR == 397
    assert _HISTORICAL_VULNERABLE_HEAD_SHA == "a756b7e3cf486cba0930c1a482c6a30e0df958f5"
    assert _HISTORICAL_VULNERABLE_BLOB_SHA == "926d528d17b7ae39ab89001657a21f7ef30af743"
    assert _CURRENT_PROTECTED_HEAD_SHA == "b88e66e81e9701404d29a0f5de4f58573ceee14f"
    assert _CURRENT_PROTECTED_BLOB_SHA == "450be87886a9668fbe39b427aaeb08fc3438dc5d"
    assert _FIXED_CANDIDATE_HEAD_SHA == "5ed7fa125bcf63df4bb548d8bc244ac4ddf0054c"
    assert _FIXED_CANDIDATE_BLOB_SHA == "b5ea69b272f571c1fd3b677c07b636f5f7ca610e"


def test_rule_detects_calendar_query_session_without_revocation_check() -> None:
    """Detect direct JWT verification on the calendar URL-token transport."""
    rule = _rule()
    assert rule["severity"] == "HIGH"
    assert rule["pattern"].search(_CALENDAR_VULNERABLE)


def test_rule_detects_stream_query_session_without_revocation_check() -> None:
    """Detect direct JWT verification on the stream URL-token transport."""
    assert _rule()["pattern"].search(_STREAM_VULNERABLE)


def test_rule_declares_source_derived_prefilters() -> None:
    """Bound expensive matching to the observed Hono query-token surface."""
    assert _rule()["required_substrings"] == (
        "c.req.query('token')",
        "verifyToken(",
        "app.get(",
    )


def test_rule_ignores_reviewed_revocation_aware_candidate() -> None:
    """Keep the PR #397 verifySessionJwt fixed candidate clean."""
    assert not _rule()["pattern"].search(_FIXED_CANDIDATE)


def test_rule_ignores_inline_revocation_check_after_signature_verification() -> None:
    """Do not flag a URL-token route that validates token_version inline."""
    assert not _rule()["pattern"].search(_EXPLICIT_INLINE_REVOCATION)


def test_rule_ignores_bearer_only_direct_verification() -> None:
    """Keep this detector limited to the collected query-token bypass family."""
    assert not _rule()["pattern"].search(_BEARER_ONLY_DIRECT_VERIFY)


def test_scan_file_emits_normalized_session_expiration_finding(tmp_path: Path) -> None:
    """Exercise production scanning over both vulnerable URL-token routes."""
    findings = _scan(_CALENDAR_VULNERABLE + _STREAM_VULNERABLE, tmp_path)
    assert findings
    assert {finding["rule_id"] for finding in findings} == {_RULE_ID}
    for finding in findings:
        assert finding["severity"] == "HIGH"
        assert finding["source"] == "appguardrail-rule"
        assert finding["confidence"] == "high"
        assert finding["cwe"] == (
            "CWE-613 - Insufficient Session Expiration",
        )


def test_scan_file_keeps_revocation_aware_candidate_clean(tmp_path: Path) -> None:
    """Verify the fixed candidate through the production scanner entrypoint."""
    assert _scan(_FIXED_CANDIDATE, tmp_path) == []
