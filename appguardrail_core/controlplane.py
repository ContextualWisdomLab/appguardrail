"""Multi-tenant control-plane store for AppGuardrail scan history.

This is the seed of the hosted platform: instead of a one-shot CLI, an org can
push every CI scan (`appguardrail.findings.v1`) to a persistent, API-key-scoped
store and query its history/trend. That persistent, multi-tenant surface is the
recurring-revenue backbone a CLI alone can't be.

Stdlib only (sqlite3 + hashlib + secrets), so it ships in the same wheel and
adds no dependency. SQLite is the ``ponytail`` starting point — swap the store
for Postgres behind the same functions when scale demands it.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Any, Iterable

from .findings import is_deploy_blocking, normalize_findings, severity_counts

_SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    api_key_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    repo TEXT,
    commit_sha TEXT,
    total INTEGER NOT NULL,
    deploy_blocking INTEGER NOT NULL,
    severity_counts TEXT NOT NULL,
    findings TEXT NOT NULL,
    FOREIGN KEY (org_id) REFERENCES orgs (id)
);
CREATE INDEX IF NOT EXISTS idx_scans_org ON scans (org_id, id DESC);
"""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def connect(db_path: str) -> sqlite3.Connection:
    """Open (and initialize) the control-plane database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.commit()
    return conn


def create_org(conn: sqlite3.Connection, name: str) -> "tuple[int, str]":
    """Create an org and return (org_id, api_key). The key is shown only here."""
    api_key = "agk_" + secrets.token_urlsafe(32)
    cur = conn.execute(
        "INSERT INTO orgs (name, api_key_hash, created_at) VALUES (?, ?, ?)",
        (name, _hash_key(api_key), _now()),
    )
    conn.commit()
    return cur.lastrowid, api_key


def org_for_key(conn: sqlite3.Connection, api_key: str) -> "int | None":
    """Return the org id for a presented API key, or None."""
    if not api_key:
        return None
    row = conn.execute(
        "SELECT id FROM orgs WHERE api_key_hash = ?", (_hash_key(api_key),)
    ).fetchone()
    return row["id"] if row else None


def add_scan(
    conn: sqlite3.Connection,
    org_id: int,
    findings: Iterable[dict[str, Any]],
    repo: "str | None" = None,
    commit_sha: "str | None" = None,
) -> dict[str, Any]:
    """Store a scan for an org, computing counts from the findings."""
    normalized = list(normalize_findings(findings))
    counts = severity_counts(normalized)
    blocking = sum(1 for f in normalized if is_deploy_blocking(f))
    created_at = _now()
    cur = conn.execute(
        "INSERT INTO scans (org_id, created_at, repo, commit_sha, total, "
        "deploy_blocking, severity_counts, findings) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            org_id,
            created_at,
            repo,
            commit_sha,
            len(normalized),
            blocking,
            json.dumps(counts),
            json.dumps(normalized),
        ),
    )
    conn.commit()
    return {
        "id": cur.lastrowid,
        "created_at": created_at,
        "total": len(normalized),
        "deploy_blocking": blocking,
        "severity_counts": counts,
    }


def list_scans(conn: sqlite3.Connection, org_id: int, limit: int = 100) -> list[dict[str, Any]]:
    """Return scan summaries for an org, newest first."""
    rows = conn.execute(
        "SELECT id, created_at, repo, commit_sha, total, deploy_blocking, severity_counts "
        "FROM scans WHERE org_id = ? ORDER BY id DESC LIMIT ?",
        (org_id, limit),
    ).fetchall()
    return [
        {
            "id": r["id"],
            "created_at": r["created_at"],
            "repo": r["repo"],
            "commit": r["commit_sha"],
            "total": r["total"],
            "deploy_blocking": r["deploy_blocking"],
            "severity_counts": json.loads(r["severity_counts"]),
        }
        for r in rows
    ]


def get_scan(conn: sqlite3.Connection, org_id: int, scan_id: int) -> "dict[str, Any] | None":
    """Return a full scan (with findings) scoped to the org, or None."""
    r = conn.execute(
        "SELECT * FROM scans WHERE id = ? AND org_id = ?", (scan_id, org_id)
    ).fetchone()
    if r is None:
        return None
    return {
        "id": r["id"],
        "created_at": r["created_at"],
        "repo": r["repo"],
        "commit": r["commit_sha"],
        "total": r["total"],
        "deploy_blocking": r["deploy_blocking"],
        "severity_counts": json.loads(r["severity_counts"]),
        "findings": json.loads(r["findings"]),
    }



def make_control_plane_server(host: str, port: int, db_path: str):
    """Build an HTTP API for scan ingest + history, scoped by API key.

    Endpoints (JSON):
      GET  /api/v1/health         -> {"status":"ok"} (no auth)
      POST /api/v1/scans          -> ingest {findings:[...], repo?, commit?}
      GET  /api/v1/scans          -> list this org's scans (summaries)
      GET  /api/v1/scans/{id}     -> full scan with findings
    Auth: Authorization: Bearer <api_key>.
    """
    import http.server

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.commit()

    class _Handler(http.server.BaseHTTPRequestHandler):
        def _json(self, code, obj):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _org(self):
            hdr = self.headers.get("Authorization", "")
            key = hdr[7:] if hdr.startswith("Bearer ") else ""
            return org_for_key(conn, key)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/api/v1/health":
                return self._json(200, {"status": "ok"})
            org = self._org()
            if org is None:
                return self._json(401, {"error": "invalid or missing API key"})
            if path == "/api/v1/scans":
                return self._json(200, {"scans": list_scans(conn, org)})
            m = re.match(r"^/api/v1/scans/(\d+)$", path)
            if m:
                scan = get_scan(conn, org, int(m.group(1)))
                return self._json(200, scan) if scan else self._json(404, {"error": "not found"})
            self._json(404, {"error": "not found"})

        def do_POST(self):
            if self.path.split("?", 1)[0] != "/api/v1/scans":
                return self._json(404, {"error": "not found"})
            org = self._org()
            if org is None:
                return self._json(401, {"error": "invalid or missing API key"})
            try:
                length = int(self.headers.get("Content-Length", 0))
                data = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, TypeError):
                return self._json(400, {"error": "invalid JSON body"})
            findings = data.get("findings") if isinstance(data, dict) else data
            if not isinstance(findings, list):
                return self._json(400, {"error": "expected a findings array or {\"findings\":[...]}"})
            meta = data if isinstance(data, dict) else {}
            summary = add_scan(conn, org, findings, meta.get("repo"), meta.get("commit"))
            self._json(201, summary)

        def log_message(self, *_args):
            pass

    return http.server.HTTPServer((host, port), _Handler)


if __name__ == "__main__":  # pragma: no cover - self-check
    conn = connect(":memory:")
    oid, key = create_org(conn, "Acme")
    assert org_for_key(conn, key) == oid
    assert org_for_key(conn, "agk_wrong") is None
    s = add_scan(
        conn, oid,
        [{"severity": "CRITICAL", "rule_id": "x", "context": "app-code"},
         {"severity": "INFO", "rule_id": "y", "context": "doc"}],
        repo="acme/app", commit_sha="abc123",
    )
    assert s["total"] == 2 and s["deploy_blocking"] == 1, s
    listed = list_scans(conn, oid)
    assert len(listed) == 1 and listed[0]["repo"] == "acme/app"
    full = get_scan(conn, oid, s["id"])
    assert full and len(full["findings"]) == 2
    # tenant isolation: another org can't read the first org's scan
    oid2, _ = create_org(conn, "Beta")
    assert get_scan(conn, oid2, s["id"]) is None
    assert list_scans(conn, oid2) == []
    print("controlplane self-check OK")
