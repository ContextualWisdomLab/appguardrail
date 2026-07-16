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
import hmac
import http.client
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import sqlite3
import warnings
from datetime import datetime, timezone
from importlib import (
    resources,
)  # nosemgrep: python.lang.compatibility.python37.python37-compatibility-importlib2
from typing import Any, Iterable
from urllib.parse import parse_qs, urlparse

from .findings import is_deploy_blocking, normalize_findings, severity_counts

_SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    api_key_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    webhook_url TEXT
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
    new_blocking INTEGER NOT NULL DEFAULT 0,
    findings TEXT NOT NULL,
    FOREIGN KEY (org_id) REFERENCES orgs (id)
);
CREATE INDEX IF NOT EXISTS idx_scans_org ON scans (org_id, id DESC);
CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'member',
    label TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (org_id) REFERENCES orgs (id)
);
"""


def _now() -> str:
    """Return the current UTC time in the persisted control-plane format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# API keys contain 256 bits of randomness, so password-style memory-hard hashing
# does not improve resistance to guessing.  It does let an unauthenticated
# request force a costly allocation, however.  A keyed, deterministic digest is
# both safe for high-entropy tokens and suitable for an indexed lookup.
_KEY_HASH_PREFIX = "hmac-sha256$v2$"
_DEFAULT_KEY_PEPPER = "appguardrail.controlplane.key.v2"
_API_KEY_PATTERN = re.compile(r"^agk_[A-Za-z0-9_-]{32,128}$")


def _key_pepper() -> bytes:
    """Return the deployment pepper used to fingerprint high-entropy API keys."""
    return os.environ.get("APPGUARDRAIL_API_KEY_PEPPER", _DEFAULT_KEY_PEPPER).encode(
        "utf-8"
    )


def _hash_key(api_key: str) -> str:
    """Return a constant-cost keyed fingerprint for a random API key."""
    digest = hmac.new(_key_pepper(), api_key.encode("utf-8"), hashlib.sha256)
    return _KEY_HASH_PREFIX + digest.hexdigest()


def _valid_api_key(api_key: str) -> bool:
    """Reject malformed or oversized bearer values before hashing or SQL work."""
    return isinstance(api_key, str) and bool(_API_KEY_PATTERN.fullmatch(api_key))


def _warn_for_legacy_key_hashes(conn: sqlite3.Connection) -> None:
    """Make the required one-time key rotation visible to operators."""
    row = conn.execute(
        "SELECT "
        "(SELECT COUNT(*) FROM keys WHERE key_hash NOT LIKE ?) + "
        "(SELECT COUNT(*) FROM orgs WHERE api_key_hash NOT LIKE ?) AS legacy_count",
        (f"{_KEY_HASH_PREFIX}%", f"{_KEY_HASH_PREFIX}%"),
    ).fetchone()
    if row and row["legacy_count"]:
        warnings.warn(
            "Legacy scrypt API-key rows require rotation; a slow compatibility "
            "fallback would permit request-driven memory exhaustion.",
            RuntimeWarning,
            stacklevel=2,
        )


def connect(db_path: str) -> sqlite3.Connection:
    """Open (and initialize) the control-plane database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.commit()
    _warn_for_legacy_key_hashes(conn)
    return conn


def create_org(conn: sqlite3.Connection, name: str) -> "tuple[int, str]":
    """Create an org and return (org_id, api_key). The key is shown only here."""
    api_key = "agk_" + secrets.token_urlsafe(32)
    key_hash = _hash_key(api_key)
    cur = conn.execute(
        "INSERT INTO orgs (name, api_key_hash, created_at) VALUES (?, ?, ?)",
        (name, key_hash, _now()),
    )
    org_id = cur.lastrowid
    conn.execute(
        "INSERT INTO keys (org_id, key_hash, role, label, created_at) VALUES (?, ?, ?, ?, ?)",
        (org_id, key_hash, "owner", "owner (bootstrap)", _now()),
    )
    conn.commit()
    return org_id, api_key


def org_for_key(conn: sqlite3.Connection, api_key: str) -> "int | None":
    """Return the org id for a presented API key, or None."""
    if not _valid_api_key(api_key):
        return None
    row = conn.execute(
        "SELECT id FROM orgs WHERE api_key_hash = ?", (_hash_key(api_key),)
    ).fetchone()
    return row["id"] if row else None


def _drift_fp(finding: dict[str, Any]) -> str:
    """Coarse identity for drift: rule + file + message head (line-independent)."""
    return f"{finding.get('rule_id')}|{finding.get('file')}|{str(finding.get('message', ''))[:80]}"


def set_webhook(conn: sqlite3.Connection, org_id: int, url: "str | None") -> None:
    """Set (or clear) the org's drift-alert webhook URL."""
    conn.execute("UPDATE orgs SET webhook_url = ? WHERE id = ?", (url or None, org_id))
    conn.commit()


def _is_slack_webhook(url: str) -> bool:
    """True if ``url`` is a Slack Incoming Webhook (host under hooks.slack.com)."""
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    return host == "hooks.slack.com" or host.endswith(".hooks.slack.com")


def _slack_escape(text: str) -> str:
    """Escape the three characters Slack treats specially in message text."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _trim(text: str, limit: int) -> str:
    """Trim ``text`` to ``limit`` chars (Slack block text has hard caps)."""
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


def _slack_blocks(
    org_name: "str | None",
    payload: dict[str, Any],
    new_findings: "list[dict[str, Any]]",
    top: int = 5,
) -> dict[str, Any]:
    """Render a drift alert as a Slack Block Kit message (header + summary).

    Lists the org, the count of newly-introduced deploy blockers, and up to
    ``top`` offending ``rule_id`` / ``file`` pairs with a ``+N more`` overflow
    line. Returns the dict POSTed to a Slack Incoming Webhook.
    """
    org = org_name or f"org {payload.get('org_id')}"
    n = payload.get("new_blocking", 0)
    repo = payload.get("repo") or "—"
    scan_id = payload.get("scan_id")

    shown = new_findings[:top]
    lines = [
        "• `{rule}` — {file}".format(
            rule=_slack_escape(str(f.get("rule_id") or "?")),
            file=_slack_escape(str(f.get("file") or "?")),
        )
        for f in shown
    ]
    remaining = len(new_findings) - len(shown)
    if remaining > 0:
        lines.append(f"• +{remaining} more")
    detail = "\n".join(lines) if lines else "_no finding details available_"

    header = f"{n} new deploy-blocking finding{'s' if n != 1 else ''}"
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": _trim(header, 150)}},
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": _trim(f"*Org:*\n{_slack_escape(org)}", 2000),
                },
                {"type": "mrkdwn", "text": f"*New blockers:*\n{n}"},
                {
                    "type": "mrkdwn",
                    "text": _trim(f"*Repo:*\n{_slack_escape(str(repo))}", 2000),
                },
                {"type": "mrkdwn", "text": f"*Scan:*\n#{scan_id}"},
            ],
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": _trim(detail, 3000)}},
    ]
    return {
        "text": _trim(f"{header} in {_slack_escape(org)}", 3000),
        "blocks": blocks,
    }


def _is_public_ip(value: str) -> bool:
    """Return whether an address is globally routable, including mapped IPv4."""
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    address = mapped or address
    return bool(
        address.is_global
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )


def _resolve_safe_url(url: str) -> "tuple[Any, str, int] | None":
    """Resolve and validate a webhook once, returning a pinned public address."""
    try:
        parsed = urlparse(
            url
        )  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except (TypeError, ValueError):
        return None
    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        return None
    host = parsed.hostname.rstrip(".").lower()
    try:
        addresses = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except (OSError, UnicodeError):
        return None
    resolved = []
    for entry in addresses:
        address = entry[4][0]
        if not _is_public_ip(address):
            return None
        if address not in resolved:
            resolved.append(address)
    if not resolved:
        return None
    return parsed, resolved[0], port


def _is_safe_url(url: str) -> bool:
    """Return whether a webhook resolves exclusively to public addresses."""
    return _resolve_safe_url(url) is not None


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a validated IP while authenticating the original TLS host."""

    def __init__(self, host: str, address: str, port: int, timeout: float):
        """Store the validated address separately from the TLS host name."""
        super().__init__(
            host, port, timeout=timeout, context=ssl.create_default_context()
        )
        self._validated_address = address

    def connect(self) -> None:
        """Open the socket to the already validated address without a DNS redo."""
        self.sock = self._create_connection(
            (self._validated_address, self.port),
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def _send_alert(
    url: str,
    payload: dict[str, Any],
    *,
    org_name: "str | None" = None,
    new_findings: "list[dict[str, Any]] | None" = None,
) -> bool:
    """Best-effort POST of a drift alert. Never raises; returns delivery success.

    For Slack Incoming Webhook URLs (host ``hooks.slack.com``) the alert is
    rendered as a Block Kit message so Slack shows a readable card; every other
    URL receives the generic JSON ``payload`` unchanged (backward compatible).
    """
    target = _resolve_safe_url(url)
    if target is None:
        return False
    parsed, address, port = target

    if _is_slack_webhook(url):
        body = _slack_blocks(org_name, payload, new_findings or [])
    else:
        body = payload

    encoded = json.dumps(body).encode("utf-8")
    host = parsed.hostname or ""
    if parsed.scheme.lower() == "https":
        connection: http.client.HTTPConnection = _PinnedHTTPSConnection(
            host, address, port, 10
        )
    else:
        connection = http.client.HTTPConnection(address, port, timeout=10)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    host_header = host if port == default_port else f"{host}:{port}"
    try:
        connection.request(
            "POST",
            path,
            body=encoded,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(encoded)),
                "Host": host_header,
            },
        )
        response = connection.getresponse()
        response.read(4096)
        # Redirects are deliberately not followed: a second URL would require a
        # second DNS resolution and could redirect the payload into private space.
        return 200 <= response.status < 300
    except (OSError, ValueError, http.client.HTTPException, ssl.SSLError):
        return False
    finally:
        connection.close()


ROLES = ("viewer", "member", "owner")
_ROLE_RANK = {role: rank for rank, role in enumerate(ROLES)}


def has_role(role: "str | None", minimum: str) -> bool:
    """True if ``role`` is at or above ``minimum`` in the viewer<member<owner order."""
    return _ROLE_RANK.get(role or "", -1) >= _ROLE_RANK.get(minimum, 99)


def create_key(
    conn: sqlite3.Connection,
    org_id: int,
    role: str = "member",
    label: "str | None" = None,
) -> "tuple[int, str]":
    """Issue a new API key for an org with a role. Returns (key_id, api_key)."""
    role = role if role in _ROLE_RANK else "member"
    api_key = "agk_" + secrets.token_urlsafe(32)
    cur = conn.execute(
        "INSERT INTO keys (org_id, key_hash, role, label, created_at) VALUES (?, ?, ?, ?, ?)",
        (org_id, _hash_key(api_key), role, label, _now()),
    )
    conn.commit()
    return cur.lastrowid, api_key


def role_for_key(conn: sqlite3.Connection, api_key: str) -> "tuple[int, str] | None":
    """Return (org_id, role) for a presented key, or None."""
    if not _valid_api_key(api_key):
        return None
    key_hash = _hash_key(api_key)
    row = conn.execute(
        "SELECT org_id, role FROM keys WHERE key_hash = ? "
        "UNION ALL SELECT id, 'owner' FROM orgs WHERE api_key_hash = ? LIMIT 1",
        (key_hash, key_hash),
    ).fetchone()
    return (row["org_id"], row["role"]) if row else None


def _record_scan(
    conn: sqlite3.Connection,
    org_id: int,
    findings: Iterable[dict[str, Any]],
    repo: "str | None" = None,
    commit_sha: "str | None" = None,
) -> "tuple[dict[str, Any], dict[str, Any] | None]":
    """Store a scan and return its summary plus any pending webhook delivery."""
    normalized = list(normalize_findings(findings))
    counts = severity_counts(normalized)
    blocking_findings = [f for f in normalized if is_deploy_blocking(f)]
    blocking = len(blocking_findings)

    prev = conn.execute(
        "SELECT findings FROM scans WHERE org_id = ? AND IFNULL(repo, '') = IFNULL(?, '') "
        "ORDER BY id DESC LIMIT 1",
        (org_id, repo),
    ).fetchone()
    prev_fps = set()
    if prev:
        prev_fps = {
            _drift_fp(f) for f in json.loads(prev["findings"]) if is_deploy_blocking(f)
        }
    new_findings = [f for f in blocking_findings if _drift_fp(f) not in prev_fps]
    new_blocking = len(new_findings)

    created_at = _now()
    cur = conn.execute(
        "INSERT INTO scans (org_id, created_at, repo, commit_sha, total, "
        "deploy_blocking, severity_counts, new_blocking, findings) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            org_id,
            created_at,
            repo,
            commit_sha,
            len(normalized),
            blocking,
            json.dumps(counts),
            new_blocking,
            json.dumps(normalized),
        ),
    )
    conn.commit()

    pending_alert = None
    if new_blocking > 0:
        row = conn.execute(
            "SELECT name, webhook_url FROM orgs WHERE id = ?", (org_id,)
        ).fetchone()
        hook = row["webhook_url"] if row else None
        if hook:
            pending_alert = {
                "url": hook,
                "payload": {
                    "event": "drift.new_blocking",
                    "org_id": org_id,
                    "scan_id": cur.lastrowid,
                    "repo": repo,
                    "commit": commit_sha,
                    "new_blocking": new_blocking,
                    "deploy_blocking": blocking,
                    "created_at": created_at,
                },
                "org_name": row["name"] if row else None,
                "new_findings": new_findings,
            }

    summary = {
        "id": cur.lastrowid,
        "created_at": created_at,
        "total": len(normalized),
        "deploy_blocking": blocking,
        "new_blocking": new_blocking,
        "severity_counts": counts,
    }
    return summary, pending_alert


def _deliver_pending_alert(pending_alert: "dict[str, Any] | None") -> bool:
    """Deliver a prepared alert without retaining a database lock."""
    if not pending_alert:
        return False
    return _send_alert(**pending_alert)


def add_scan(
    conn: sqlite3.Connection,
    org_id: int,
    findings: Iterable[dict[str, Any]],
    repo: "str | None" = None,
    commit_sha: "str | None" = None,
) -> dict[str, Any]:
    """Store a scan for an org, computing counts from the findings."""
    summary, pending_alert = _record_scan(
        conn, org_id, findings, repo=repo, commit_sha=commit_sha
    )
    _deliver_pending_alert(pending_alert)
    return summary


def list_scans(
    conn: sqlite3.Connection, org_id: int, limit: int = 100, offset: int = 0
) -> list[dict[str, Any]]:
    """Return scan summaries for an org, newest first."""
    rows = conn.execute(
        "SELECT id, created_at, repo, commit_sha, total, deploy_blocking, new_blocking, severity_counts "
        "FROM scans WHERE org_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
        (org_id, limit, max(0, offset)),
    ).fetchall()
    return [
        {
            "id": r["id"],
            "created_at": r["created_at"],
            "repo": r["repo"],
            "commit": r["commit_sha"],
            "total": r["total"],
            "deploy_blocking": r["deploy_blocking"],
            "new_blocking": r["new_blocking"],
            "severity_counts": json.loads(r["severity_counts"]),
        }
        for r in rows
    ]


def scan_trend(
    conn: sqlite3.Connection, org_id: int, limit: int = 30
) -> list[dict[str, Any]]:
    """Oldest->newest deploy_blocking/new_blocking series for charting."""
    rows = conn.execute(
        "SELECT created_at, deploy_blocking, new_blocking FROM scans "
        "WHERE org_id = ? ORDER BY id DESC LIMIT ?",
        (org_id, max(1, limit)),
    ).fetchall()
    return [
        {
            "created_at": r["created_at"],
            "deploy_blocking": r["deploy_blocking"],
            "new_blocking": r["new_blocking"],
        }
        for r in reversed(rows)
    ]


def get_scan(
    conn: sqlite3.Connection, org_id: int, scan_id: int
) -> "dict[str, Any] | None":
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
        "new_blocking": r["new_blocking"],
        "severity_counts": json.loads(r["severity_counts"]),
        "findings": json.loads(r["findings"]),
    }


def console_html() -> bytes:
    """Return the packaged org-console HTML, or a minimal fallback."""
    try:
        path = resources.files("scanner").joinpath("dashboard", "console.html")
        return path.read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return b"<!doctype html><title>AppGuardrail Console</title><p>Console asset missing.</p>"


def make_control_plane_server(
    host: str, port: int, db_path: str, client_timeout: float = 10.0
):
    """Build an HTTP API for scan ingest + history, scoped by API key.

    Endpoints (JSON):
      GET  /api/v1/health         -> {"status":"ok"} (no auth)
      POST /api/v1/scans          -> ingest {findings:[...], repo?, commit?}
      GET  /api/v1/scans          -> list this org's scans (summaries)
      GET  /api/v1/scans/{id}     -> full scan with findings
    Auth: Authorization: Bearer <api_key>.
    """
    import http.server
    import threading

    try:
        client_timeout = float(client_timeout)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Control-plane client timeout must be a positive number"
        ) from exc
    if client_timeout <= 0:
        raise ValueError("Control-plane client timeout must be a positive number")

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    conn.commit()
    _warn_for_legacy_key_hashes(conn)
    db_lock = threading.RLock()
    auth_slots = threading.BoundedSemaphore(32)
    console = console_html()

    class _Handler(http.server.BaseHTTPRequestHandler):
        """Serve the tenant-scoped control-plane JSON API."""

        def setup(self):
            """Bound how long one client may occupy a request thread."""
            super().setup()
            self.connection.settimeout(client_timeout)

        def _json(self, code, obj):
            """Write one bounded JSON response."""
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _auth(self):
            """Authenticate a bounded bearer value without expensive KDF work."""
            hdr = self.headers.get("Authorization", "")
            key = hdr[7:] if hdr.startswith("Bearer ") else ""
            if not _valid_api_key(key) or not auth_slots.acquire(blocking=False):
                return None
            try:
                with db_lock:
                    return role_for_key(conn, key)
            finally:
                auth_slots.release()

        def do_GET(self):
            """Serve health, console, and authenticated scan queries."""
            parsed = urlparse(self.path)
            path = parsed.path
            qs = parse_qs(parsed.query)

            def _qint(name, default, lo, hi):
                """Parse and clamp one integer query parameter."""
                # Clamp: sqlite treats LIMIT -1 as "no limit", so never pass
                # negatives through; hi keeps a single request bounded.
                try:
                    value = int(qs.get(name, [default])[0])
                except (ValueError, TypeError):
                    return default
                return max(lo, min(hi, value))

            if path in ("/", "/console", "/index.html"):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(console)))
                self.end_headers()
                self.wfile.write(console)
                return
            if path == "/api/v1/health":
                return self._json(200, {"status": "ok"})
            auth = self._auth()
            if auth is None:
                return self._json(401, {"error": "invalid or missing API key"})
            org, _role = auth
            if path == "/api/v1/scans":
                with db_lock:
                    scans = list_scans(
                        conn,
                        org,
                        _qint("limit", 100, 1, 1000),
                        _qint("offset", 0, 0, 10**9),
                    )
                return self._json(200, {"scans": scans})
            if path == "/api/v1/scans/trend":
                with db_lock:
                    trend = scan_trend(conn, org, _qint("limit", 30, 1, 365))
                return self._json(200, {"trend": trend})
            m = re.match(r"^/api/v1/scans/(\d+)$", path)
            if m:
                with db_lock:
                    scan = get_scan(conn, org, int(m.group(1)))
                return (
                    self._json(200, scan)
                    if scan
                    else self._json(404, {"error": "not found"})
                )
            return self._json(404, {"error": "not found"})

        _MAX_BODY = 10 * 1024 * 1024  # 10 MiB — plenty for findings, blocks OOM posts

        def _body(self):
            """Read one size-bounded JSON request body."""
            try:
                length = int(self.headers.get("Content-Length", 0))
            except (ValueError, TypeError):
                return None
            if length < 0 or length > self._MAX_BODY:
                # Negative reads until EOF; oversized bodies exhaust memory.
                return None
            try:
                raw = self.rfile.read(length)
                if len(raw) != length:
                    return None
                return json.loads(raw or b"{}")
            except (OSError, ValueError, TypeError):
                return None

        def do_POST(self):
            """Handle authenticated webhook, key, and scan mutations."""
            path = self.path.split("?", 1)[0]
            if path not in ("/api/v1/scans", "/api/v1/webhook", "/api/v1/keys"):
                return self._json(404, {"error": "not found"})
            auth = self._auth()
            if auth is None:
                return self._json(401, {"error": "invalid or missing API key"})
            org, role = auth

            if path == "/api/v1/webhook":
                if not has_role(role, "owner"):
                    return self._json(403, {"error": "owner role required"})
                body = self._body()
                if body is None:
                    return self._json(400, {"error": "invalid JSON body"})
                with db_lock:
                    set_webhook(conn, org, (body or {}).get("url"))
                return self._json(200, {"webhook_url": (body or {}).get("url")})

            if path == "/api/v1/keys":
                if not has_role(role, "owner"):
                    return self._json(403, {"error": "owner role required"})
                body = self._body()
                if body is None:
                    return self._json(400, {"error": "invalid JSON body"})
                new_role = (body or {}).get("role", "member")
                with db_lock:
                    _kid, new_key = create_key(
                        conn, org, new_role, (body or {}).get("label")
                    )
                return self._json(
                    201,
                    {
                        "api_key": new_key,
                        "role": new_role if new_role in ROLES else "member",
                    },
                )
            if not has_role(role, "member"):
                return self._json(
                    403, {"error": "member role required to ingest scans"}
                )
            data = self._body()
            if data is None:
                return self._json(400, {"error": "invalid JSON body"})
            findings = data.get("findings") if isinstance(data, dict) else data
            if not isinstance(findings, list):
                return self._json(
                    400, {"error": 'expected a findings array or {"findings":[...]}'}
                )
            meta = data if isinstance(data, dict) else {}
            with db_lock:
                summary, pending_alert = _record_scan(
                    conn, org, findings, meta.get("repo"), meta.get("commit")
                )
            # Network delivery is intentionally outside the global SQLite lock,
            # so one slow webhook cannot stall every tenant's reads and writes.
            _deliver_pending_alert(pending_alert)
            return self._json(201, summary)

        def log_message(self, format, *args):
            """Suppress default logging."""
            return None

    class _ThreadingHTTPServer(http.server.ThreadingHTTPServer):
        """Thread-per-request server with bounded shutdown behavior."""

        daemon_threads = True
        block_on_close = False
        request_queue_size = 128

    return _ThreadingHTTPServer((host, port), _Handler)


if __name__ == "__main__":  # pragma: no cover - self-check
    # Executable module self-checks; these assertions do not validate user input.
    conn = connect(":memory:")
    oid, key = create_org(conn, "Acme")
    assert org_for_key(conn, key) == oid  # noqa: S101  # nosec B101
    assert org_for_key(conn, "agk_wrong") is None  # noqa: S101  # nosec B101
    s = add_scan(
        conn,
        oid,
        [
            {"severity": "CRITICAL", "rule_id": "x", "context": "app-code"},
            {"severity": "INFO", "rule_id": "y", "context": "doc"},
        ],
        repo="acme/app",
        commit_sha="abc123",
    )
    assert s["total"] == 2 and s["deploy_blocking"] == 1, s  # noqa: S101  # nosec B101
    listed = list_scans(conn, oid)
    assert len(listed) == 1 and listed[0]["repo"] == "acme/app"  # noqa: S101  # nosec B101
    full = get_scan(conn, oid, s["id"])
    assert full and len(full["findings"]) == 2  # noqa: S101  # nosec B101
    # tenant isolation: another org can't read the first org's scan
    oid2, _ = create_org(conn, "Beta")
    assert get_scan(conn, oid2, s["id"]) is None  # noqa: S101  # nosec B101
    assert list_scans(conn, oid2) == []  # noqa: S101  # nosec B101
    print("controlplane self-check OK")
