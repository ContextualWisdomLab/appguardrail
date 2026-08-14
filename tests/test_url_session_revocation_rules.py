"""Source-derived regressions for URL-token endpoints that bypass session revocation."""

from pathlib import Path

from scanner.cli.appguardrail import SCAN_RULES, _scan_file

_RULE_ID = "javascript-url-session-token-without-revocation"
_SOURCE_REPOSITORY = "ContextualWisdomLab/scopeweave"
_VULNERABLE_HEAD_SHA = "a756b7e3cf486cba0930c1a482c6a30e0df958f5"
_VULNERABLE_BLOB_SHA = "926d528d17b7ae39ab89001657a21f7ef30af743"
_FIXED_HEAD_SHA = "5ed7fa125bcf63df4bb548d8bc244ac4ddf0054c"
_FIXED_BLOB_SHA = "b5ea69b272f571c1fd3b677c07b636f5f7ca610e"

_VULNERABLE_SOURCE = '''
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
  if (!p) return c.json({ error: 'not found' }, 404);
});

app.get('/api/projects/:id/stream', (c) => {
  const header = c.req.header('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : (c.req.query('token') || '');
  let user;
  try { user = verifyToken(token); } catch { return c.json({ error: 'unauthorized' }, 401); }
  const id = c.req.param('id');
  if (!projectAccess(user.sub, id)) return c.json({ error: 'not found' }, 404);
  return new Response('stream');
});
'''

_FIXED_SOURCE = '''
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
  const p = projectAccess(uid, c.req.param('id'));
  if (!p) return c.json({ error: 'not found' }, 404);
});

app.get('/api/projects/:id/stream', (c) => {
  const header = c.req.header('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : (c.req.query('token') || '');
  let user;
  try { user = verifySessionJwt(token); }
  catch { return c.json({ error: 'unauthorized' }, 401); }
  const id = c.req.param('id');
  if (!projectAccess(user.sub, id)) return c.json({ error: 'not found' }, 404);
  return new Response('stream');
});
'''

_INLINE_VERSION_CHECK_SOURCE = '''
app.get('/api/projects/:id/stream', (c) => {
  const token = c.req.query('token') || '';
  let user;
  try {
    user = verifyToken(token);
    const current = db.prepare('SELECT token_version FROM users WHERE id = ?').get(user.sub);
    if (!current || (user.tv || 0) !== current.token_version) {
      return c.json({ error: 'unauthorized' }, 401);
    }
  } catch { return c.json({ error: 'unauthorized' }, 401); }
  return new Response('stream');
});
'''

_NON_URL_TOKEN_SOURCE = '''
app.get('/api/projects/:id/stream', requireAuth, (c) => {
  const user = c.get('user');
  return new Response(user.sub);
});
'''


def _rules() -> tuple[dict, ...]:
    """Return the two route-specific signatures under one session weakness identity."""
    matches = tuple(rule for rule in SCAN_RULES if rule["id"] == _RULE_ID)
    assert len(matches) == 2, f"expected two loaded variants for {_RULE_ID}"
    return matches


def _scan(source: str, tmp_path: Path) -> list[dict]:
    """Run the production scanner and isolate this detector family."""
    source_file = tmp_path / "app.mjs"
    source_file.write_text(source, encoding="utf-8")
    return [
        finding
        for finding in _scan_file(source_file, tmp_path)
        if finding["rule_id"] == _RULE_ID
    ]


def test_source_provenance_pins_scopeweave_session_objects() -> None:
    """Keep the detector tied to the exact vulnerable and reviewed fixed blobs."""
    assert _SOURCE_REPOSITORY == "ContextualWisdomLab/scopeweave"
    assert _VULNERABLE_HEAD_SHA == "a756b7e3cf486cba0930c1a482c6a30e0df958f5"
    assert _VULNERABLE_BLOB_SHA == "926d528d17b7ae39ab89001657a21f7ef30af743"
    assert _FIXED_HEAD_SHA == "5ed7fa125bcf63df4bb548d8bc244ac4ddf0054c"
    assert _FIXED_BLOB_SHA == "b5ea69b272f571c1fd3b677c07b636f5f7ca610e"


def test_packaged_variants_detect_calendar_and_stream_revocation_bypasses() -> None:
    """Detect both query-token routes that call signature-only JWT verification."""
    rules = _rules()
    assert all(rule["severity"] == "HIGH" for rule in rules)
    assert sum(bool(rule["pattern"].search(_VULNERABLE_SOURCE)) for rule in rules) == 2


def test_packaged_variants_declare_route_specific_prefilters() -> None:
    """Avoid evaluating either multiline expression for unrelated JavaScript."""
    assert {rule["required_substrings"] for rule in _rules()} == {
        ("calendar.ics", "c.req.query('token')", "verifyToken(raw)"),
        ("/stream", "c.req.query('token')", "verifyToken(token)"),
    }


def test_packaged_variants_ignore_shared_database_revocation_helper() -> None:
    """Keep the reviewed shared `verifySessionJwt` repair negative."""
    assert all(not rule["pattern"].search(_FIXED_SOURCE) for rule in _rules())


def test_packaged_variants_ignore_inline_token_version_check() -> None:
    """Do not flag a route that verifies current database-backed token_version."""
    assert all(
        not rule["pattern"].search(_INLINE_VERSION_CHECK_SOURCE) for rule in _rules()
    )


def test_packaged_variants_ignore_middleware_only_session_transport() -> None:
    """Require the source-derived URL-token transport rather than bearer middleware."""
    assert all(not rule["pattern"].search(_NON_URL_TOKEN_SOURCE) for rule in _rules())


def test_scan_file_emits_two_normalized_session_findings(tmp_path: Path) -> None:
    """Exercise both vulnerable routes through the exact production scanner."""
    findings = _scan(_VULNERABLE_SOURCE, tmp_path)
    assert len(findings) == 2
    assert all(finding["severity"] == "HIGH" for finding in findings)
    assert all(finding["confidence"] == "high" for finding in findings)
    assert all(finding["source"] == "appguardrail-rule" for finding in findings)
    assert all(
        "CWE-613 - Insufficient Session Expiration" in finding["cwe"]
        for finding in findings
    )


def test_scan_file_keeps_reviewed_revocation_fix_clean(tmp_path: Path) -> None:
    """Keep the reviewed route-level repair clean through production scanning."""
    assert _scan(_FIXED_SOURCE, tmp_path) == []
