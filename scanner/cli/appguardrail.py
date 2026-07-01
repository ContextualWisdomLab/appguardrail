#!/usr/bin/env python3
"""
appguardrail - Security guardrails for AI-built apps

Usage:
  appguardrail init [--tool <tool>] [--stack <stack>]
  appguardrail scan [--trivy] [--external auto|off] [--bandit] [--ruff] [--semgrep] [--zap-baseline <url>] [--codegraph] [<path>]
  appguardrail monitor
  appguardrail review [--stack <stack>] [--db <db>] [--payments <payments>]
  appguardrail hook [--codegraph]
  appguardrail --help
  appguardrail --version

Commands:
  init      Install security rules into your project
  scan      Run a lightweight security scan on a directory
  monitor   Install a GitHub Actions monitor workflow
  review    Generate an AI review prompt for your stack
  hook      Install a pre-commit hook to block vulnerabilities

Options:
  --tool    AI coding tool: auto, codex, copilot, cursor, claude-code, windsurf, lovable (default: auto)
  --stack   Tech stack: nextjs, nextjs-supabase, nextjs-firebase, remix, sveltekit
  --db      Database/backend: supabase, firebase, prisma, drizzle
  --payments  Payment provider: stripe
  --trivy  Also run Trivy filesystem scan
  --external  Auto-discover installed SAST/DAST engines for detected languages (default: auto)
  --bandit  Force-run Bandit Python SAST
  --ruff  Force-run Ruff Bandit-compatible security rules
  --semgrep  Force-run Semgrep multi-language SAST
  --zap-baseline  Run OWASP ZAP baseline scan against a URL
  --codegraph  Initialize or sync a CodeGraph index before scanning
  --help    Show this help message
  --version Show version
"""

import argparse
import fnmatch
import importlib.resources as resources
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

__version__ = "0.1.1"

# ---------------------------------------------------------------------------
# Rule templates
# ---------------------------------------------------------------------------

RULES_CURSOR = """\
# AppGuardrail Security Rules

- Every API route must verify authentication before accessing data.
- For every user-owned resource, verify owner_id matches the current session user.
- Never use SUPABASE_SERVICE_ROLE_KEY or any admin key in client-side code.
- Always verify Stripe webhook signatures with stripe.webhooks.constructEvent.
- Validate all inputs (body, params, query) with a schema library before use.
- Return 403 Forbidden for ownership violations, not 404 or 200.
- File uploads must validate type, size, and filename server-side.
- Never set CORS to allow all origins on authenticated endpoints.
- Add tests for cross-user access denial on every resource endpoint.

See https://github.com/ContextualWisdomLab/appguardrail for full rules and checklists.
"""

RULES_CLAUDE = """\
## AppGuardrail Security Guardrails

Apply the following security rules to all code you generate:

1. **Authentication**: Check authentication as the first operation in every API handler.
2. **Authorization**: Verify resource ownership (owner_id === session.user.id) server-side.
3. **Secrets**: Never use NEXT_PUBLIC_ prefix on secret keys or service role keys.
4. **Input validation**: Validate all inputs with Zod or equivalent before processing.
5. **Stripe**: Always verify webhook signatures before processing payment events.
6. **Supabase**: Use getUser() (not getSession()) server-side; RLS on all tables.
7. **Files**: Validate type, size, and generate server-side filenames for uploads.
8. **CORS**: Restrict to known origins on authenticated endpoints.

Return 401 for unauthenticated requests, 403 for ownership violations.

See https://github.com/ContextualWisdomLab/appguardrail for full rules and checklists.
"""

RULES_CODEX = """\
# AppGuardrail Security Guardrails

When working in this repository, apply these security rules before proposing,
editing, or merging code:

- Check authentication at the start of every protected API handler.
- Verify resource ownership server-side before returning user-owned data.
- Never expose service-role, admin, Stripe secret, or webhook signing keys to client code.
- Validate request body, params, query, uploaded files, and webhook payloads server-side.
- Verify Stripe webhook signatures before processing payment events.
- Confirm Supabase RLS or equivalent authorization is enabled before trusting client filters.
- Run `appguardrail scan --codegraph .` before merging security-sensitive changes when CodeGraph is installed.
- Treat AppGuardrail critical/high findings as deploy blockers unless the finding is in docs, tests, examples, or scanner fixtures.

If CodeGraph is available, use it for call graph, blast radius, and ownership-flow checks before broad file reads.
"""

RULES_COPILOT = """\
# AppGuardrail Security Instructions

Apply these rules when suggesting code, reviewing pull requests, or generating fixes:

- Protected routes must authenticate first and authorize user-owned resources server-side.
- Do not place service-role keys, admin keys, Stripe secrets, or webhook secrets in client code.
- Validate all request inputs and uploaded files before use.
- Verify Stripe webhook signatures with the raw body and signing secret.
- Prefer tests that prove cross-user access returns 403.
- Run or recommend `appguardrail scan --codegraph .` for security-sensitive changes when CodeGraph is installed.
- Treat AppGuardrail critical/high findings in app code as deploy blockers.
"""

RULES_WINDSURF = RULES_CURSOR  # Windsurf uses the same format

RULES_LOVABLE = """\
# AppGuardrail Secure Build Checklist for Lovable

Use this checklist when building or reviewing an app generated with Lovable.
Paste the relevant sections as context into your Lovable prompt to enforce
security from the start.

## Prompt Prefix

Before generating any code, apply these security rules:

1. Every API route or server action must check authentication before accessing data.
2. Every resource endpoint must verify the authenticated user owns the requested record.
3. Never expose SUPABASE_SERVICE_ROLE_KEY or any admin key to the client.
4. Enable Supabase Row Level Security on every table that stores user data.
5. Validate all inputs (body, params, query) before processing.
6. Verify Stripe webhook signatures before processing payment events.
7. Never set CORS to allow all origins on authenticated endpoints.
8. Generate secure server-side filenames for uploads; validate type and size.

## Pre-Launch Security Checklist

- [ ] All protected pages and APIs require authentication.
- [ ] Every user-owned resource verifies ownership server-side.
- [ ] Supabase RLS is enabled on user-data tables.
- [ ] Service role keys and privileged API keys never reach browser code.
- [ ] `.env` files are ignored and secrets are not committed.
- [ ] Stripe webhooks call `stripe.webhooks.constructEvent`.
- [ ] Payment prices and amounts are selected server-side.
- [ ] Uploads validate type, size, and generated filenames server-side.
- [ ] Security headers and restricted CORS are configured before deploy.
"""

CHECKLIST_TEMPLATE = """\
# AppGuardrail Security Checklist

Generated by appguardrail init. Review before launching.

## Authentication
- [ ] All protected routes check authentication server-side
- [ ] Unauthenticated requests return 401
- [ ] Session tokens are stored securely

## Authorization
- [ ] Every resource endpoint verifies ownership (owner_id === session.user.id)
- [ ] Users cannot access each other's data by changing IDs
- [ ] Admin routes are protected by role checks

## Secrets
- [ ] No hardcoded secrets in source code
- [ ] .env files are in .gitignore
- [ ] No NEXT_PUBLIC_ prefix on secret keys

## Database
- [ ] Row Level Security enabled on all user-data tables (Supabase)
- [ ] Firebase rules do not use allow read, write: if true

## Payments
- [ ] Stripe webhook signature verified with constructEvent
- [ ] Prices fetched server-side, not from client request

## Deployment
- [ ] Security headers configured (X-Frame-Options, CSP, etc.)
- [ ] CORS restricted to known origins
- [ ] npm audit clean (no critical/high vulnerabilities)

See https://github.com/ContextualWisdomLab/appguardrail for full checklists.
"""

MONITOR_WORKFLOW = """\
name: AppGuardrail Monitor

on:
  pull_request:
  push:
    branches: [main, master, develop]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.x"

      - name: Install AppGuardrail
        run: python -m pip install --disable-pip-version-check appguardrail

      - name: Run AppGuardrail deploy gate
        run: appguardrail scan .
"""

# ---------------------------------------------------------------------------
# Scan patterns
# ---------------------------------------------------------------------------

SCAN_RULES = [
    {
        "id": "python-insecure-deserialization",
        "pattern": re.compile(
            r"\b(?:pickle\.(?:load|loads|Unpickler)|marshal\.(?:load|loads)|yaml\.(?:load|unsafe_load))\s*\(",
            re.MULTILINE,
        ),
        "severity": "CRITICAL",
        "message": "Insecure deserialization detected. Loading untrusted data with pickle, marshal, yaml.load, or yaml.unsafe_load can lead to arbitrary code execution. [OWASP A08:2021 - Software and Data Integrity Failures]",
        "extensions": [".py"],
    },
    {
        "id": "hardcoded-stripe-secret",
        "pattern": re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{24,}", re.MULTILINE),
        "severity": "CRITICAL",
        "message": "Hardcoded Stripe secret key detected. Rotate this key immediately. [OWASP A07:2021 - Identification and Authentication Failures]",
        "extensions": None,
    },
    {
        "id": "hardcoded-openai-key",
        "pattern": re.compile(r"sk-[A-Za-z0-9]{32,}", re.MULTILINE),
        "severity": "CRITICAL",
        "message": "Possible hardcoded OpenAI API key detected. [OWASP A07:2021 - Identification and Authentication Failures]",
        "extensions": None,
    },
    {
        "id": "next-public-secret",
        "pattern": re.compile(
            r"NEXT_PUBLIC_(?:STRIPE_SECRET|SUPABASE_SERVICE_ROLE|DATABASE|JWT_SECRET|NEXTAUTH_SECRET|API_SECRET)",
            re.IGNORECASE | re.MULTILINE,
        ),
        "severity": "CRITICAL",
        "message": "Secret environment variable uses NEXT_PUBLIC_ prefix — this exposes it to the browser bundle. [OWASP A05:2021 - Security Misconfiguration]",
        "extensions": None,
    },
    {
        "id": "supabase-service-role-client",
        "pattern": re.compile(
            r"NEXT_PUBLIC_.*SERVICE_ROLE", re.IGNORECASE | re.MULTILINE
        ),
        "severity": "CRITICAL",
        "message": "Supabase service role key exposed to the client via NEXT_PUBLIC_ prefix. [OWASP A05:2021 - Security Misconfiguration]",
        "extensions": [
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".env",
            ".env.local",
            ".env.production",
        ],
    },
    {
        "id": "firebase-allow-all",
        "pattern": re.compile(
            r"allow\s+(?:read|write|read,\s*write)\s*:\s*if\s+true", re.MULTILINE
        ),
        "severity": "CRITICAL",
        "message": "Firebase/Firestore rule allows unrestricted read/write access. Add authentication and ownership checks. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".rules"],
    },
    {
        "id": "todo-skip-auth",
        "pattern": re.compile(
            r"(?i)(?:todo|fixme|hack|temp)[^\n]{0,50}(?:auth|security|permission|check|protect)",
            re.MULTILINE,
        ),
        "severity": "HIGH",
        "message": "Comment suggests auth/security check was deferred. Verify this is not deployed to production. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".ts", ".tsx", ".js", ".jsx", ".py"],
    },
    {
        "id": "dangerous-cors",
        "pattern": re.compile(r"Access-Control-Allow-Origin['\",\s]*[*]", re.MULTILINE),
        "severity": "HIGH",
        "message": "CORS set to allow all origins (*). Restrict to known domains. [OWASP A05:2021 - Security Misconfiguration]",
        "extensions": [".ts", ".tsx", ".js", ".jsx", ".py"],
    },
    {
        "id": "hardcoded-database-url",
        "pattern": re.compile(
            r'(?i)(?:DATABASE_URL|POSTGRES_URL)\s*[=:]\s*["\x27](?:postgres|postgresql|mysql)://\S+',
            re.MULTILINE,
        ),
        "severity": "CRITICAL",
        "message": "Hardcoded database connection string detected. [OWASP A07:2021 - Identification and Authentication Failures]",
        "extensions": None,
    },
    {
        "id": "hardcoded-jwt-secret",
        "pattern": re.compile(
            r'(?i)(?:JWT_SECRET|NEXTAUTH_SECRET)\s*[=:]\s*["\x27][^"\x27\s]{8,}["\x27]',
            re.MULTILINE,
        ),
        "severity": "CRITICAL",
        "message": "Hardcoded JWT/NextAuth secret detected. [OWASP A02:2021 - Cryptographic Failures]",
        "extensions": None,
    },
    {
        "id": "stripe-webhook-no-verify",
        "pattern": re.compile(
            r'constructEvent\s*\([^)]*(?:undefined|""|\'\')\s*\)', re.MULTILINE
        ),
        "severity": "CRITICAL",
        "message": "Stripe constructEvent called with empty/undefined webhook secret. [OWASP A08:2021 - Software and Data Integrity Failures]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "mock-session-in-handler",
        "pattern": re.compile(
            r'const\s+(?:session|user)\s*=\s*\{\s*(?:user\s*:\s*)?\{\s*id\s*:\s*["\x27]',
            re.MULTILINE,
        ),
        "severity": "HIGH",
        "message": "Mock or hardcoded session/user object detected in route handler. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "dangerous-eval",
        "pattern": re.compile(r"\beval\s*\(", re.MULTILINE),
        "severity": "CRITICAL",
        "message": "Use of eval() detected. This is a critical risk for arbitrary code execution and injection attacks. [OWASP A03:2021 - Injection]",
        "extensions": [".js", ".jsx", ".ts", ".tsx", ".py"],
    },
    {
        "id": "react-dangerously-set-inner-html",
        "pattern": re.compile(r"dangerouslySetInnerHTML\s*=", re.MULTILINE),
        "severity": "HIGH",
        "message": "Use of dangerouslySetInnerHTML detected. This can lead to Cross-Site Scripting (XSS) if input is not sanitized. [OWASP A03:2021 - Injection]",
        "extensions": [".jsx", ".tsx"],
    },
    {
        "id": "sql-injection-risk",
        "pattern": re.compile(
            r'(?i)(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|["\'].*?["\']\s*\+\s*[a-zA-Z0-9_]+)',
            re.MULTILINE,
        ),
        "severity": "CRITICAL",
        "message": "Potential SQL injection detected: string concatenation or template literal in database query. [OWASP A03:2021 - Injection]",
        "extensions": [".ts", ".tsx", ".js", ".jsx", ".py"],
    },
    {
        "id": "node-command-injection",
        "pattern": re.compile(
            r'(?i)\b(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|["\'].*?["\']\s*\+\s*[a-zA-Z0-9_]+)'
        ),
        "severity": "CRITICAL",
        "message": "Potential Command Injection detected: string concatenation or template literal in child_process execution. [OWASP A03:2021 - Injection]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "python-command-injection",
        "pattern": re.compile(
            r"(?i)(?:os\.system|subprocess\.(?:Popen|run|call|check_call|check_output))\s*\([^)]*shell\s*=\s*True"
        ),
        "severity": "CRITICAL",
        "message": "Potential Command Injection detected: shell=True used in Python subprocess/os command. [OWASP A03:2021 - Injection]",
        "extensions": [".py"],
    },
    {
        "id": "path-traversal-risk",
        "pattern": re.compile(
            r'(?i)\b(?:fs\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)|open)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|["\'].*?["\']\s*\+\s*[a-zA-Z0-9_]+|f["\'][^"\']*\{[^}]+\}[^"\']*["\'])'
        ),
        "severity": "CRITICAL",
        "message": "Potential Path Traversal detected: dynamic path constructed using template literals, f-strings, or concatenation in file operations. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".ts", ".tsx", ".js", ".jsx", ".py"],
    },
    {
        "id": "browser-localstorage-sensitive-state",
        "pattern": re.compile(
            r"\blocalStorage\.setItem\s*\([^,\n]+,\s*(?:JSON\.stringify\s*\(|[^)]*(?:token|jwt|session|user|project|task|dsn|database|credential))",
            re.IGNORECASE | re.MULTILINE,
        ),
        "severity": "HIGH",
        "message": "Client-side localStorage persistence of sensitive or user-controlled app state detected. Prefer server-side storage, HttpOnly cookies for tokens, or encrypted browser storage. [OWASP A02:2021 - Cryptographic Failures]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "dom-xss-html-sink",
        "pattern": re.compile(
            r"\b(?:innerHTML|outerHTML)\s*=|\binsertAdjacentHTML\s*\(",
            re.MULTILINE,
        ),
        "severity": "HIGH",
        "message": "HTML injection sink detected. Ensure attacker-controlled values are encoded or sanitized before reaching innerHTML, outerHTML, or insertAdjacentHTML. [OWASP A03:2021 - Injection]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "unsafe-inline-script-csp",
        "pattern": re.compile(
            r"(?i)(?:content-security-policy[^;\n]*script-src[^;\n]*'unsafe-inline'|script-src[^;\n]*'unsafe-inline')",
            re.MULTILINE,
        ),
        "severity": "HIGH",
        "message": "Content Security Policy allows unsafe inline scripts. Remove 'unsafe-inline' from script-src or use nonces/hashes. [OWASP A05:2021 - Security Misconfiguration]",
        "extensions": [".html", ".htm", ".js", ".jsx", ".ts", ".tsx"],
    },
    {
        "id": "frontend-database-dsn-exposure",
        "pattern": re.compile(
            r"(?i)\b(?:dsn|databaseUrl|database_url)\b[^\n]{0,80}\b(?:useState|useRef|input|placeholder|value|localStorage|sessionStorage)\b|\b(?:useState|useRef|input|placeholder|value|localStorage|sessionStorage)\b[^\n]{0,80}\b(?:dsn|databaseUrl|database_url)\b",
            re.MULTILINE,
        ),
        "severity": "HIGH",
        "message": "Database DSN or connection string appears to be collected, stored, or rendered in client-side code. Keep database credentials server-side. [OWASP A02:2021 - Cryptographic Failures]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "upload-filename-path-traversal-risk",
        "pattern": re.compile(
            r"(?i)(?:os\.path\.join\s*\([^)\n]*(?:file|upload|attachment)\w*\.filename|Path\s*\([^)\n]*\)\s*/\s*(?:file|upload|attachment)\w*\.filename|/\s*(?:file|upload|attachment)\w*\.filename)",
            re.MULTILINE,
        ),
        "severity": "HIGH",
        "message": "Uploaded filename is used in a filesystem path. Sanitize with a strict allowlist and verify the resolved path stays inside the intended directory. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".py"],
    },
    {
        "id": "python-dynamic-sql",
        "pattern": re.compile(
            r"(?is)(?:execute|query)\s*\(\s*(?:f[\"']\s*(?:select|insert|update|delete|with)\b[^\"']*\{[^}]+\}|[\"']\s*(?:select|insert|update|delete|with)\b[^\"']*[\"']\s*(?:\+|%))",
        ),
        "severity": "CRITICAL",
        "message": "Dynamic SQL query construction detected. Use parameterized queries or query-builder binding instead of string formatting or concatenation. [OWASP A03:2021 - Injection]",
        "extensions": [".py"],
    },
    {
        "id": "python-jwt-decode-without-algorithms",
        "pattern": re.compile(
            r"jwt\.decode\s*\((?:(?!algorithms\s*=).){0,400}\)",
            re.IGNORECASE | re.DOTALL,
        ),
        "severity": "CRITICAL",
        "message": "JWT decode call does not appear to pin accepted algorithms. Explicitly require expected algorithms and validate issuer, audience, expiry, and key id. [OWASP A07:2021 - Identification and Authentication Failures]",
        "extensions": [".py"],
    },
    {
        "id": "python-subprocess-string-command",
        "pattern": re.compile(
            r"(?i)subprocess\.(?:run|Popen|call|check_call|check_output)\s*\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*\+)",
            re.MULTILINE,
        ),
        "severity": "HIGH",
        "message": "Subprocess command is built as a formatted or concatenated string. Pass an argument list and validate attacker-controlled command arguments. [OWASP A03:2021 - Injection]",
        "extensions": [".py"],
    },
    {
        "id": "python-permissive-cors",
        "pattern": re.compile(
            r"(?i)(?:allow_origins|origins)\s*=\s*\[\s*[\"']\*[\"']\s*\]",
            re.MULTILINE,
        ),
        "severity": "HIGH",
        "message": "CORS allows every origin. Restrict authenticated APIs to known origins. [OWASP A05:2021 - Security Misconfiguration]",
        "extensions": [".py"],
    },
    {
        "id": "client-side-dev-user-auth",
        "pattern": re.compile(
            r"(?i)(?:dev-user|x-dev-user|devUser)[^\n]{0,100}(?:auth|user|headers|localStorage|useState)|(?:auth|user|headers|localStorage|useState)[^\n]{0,100}(?:dev-user|x-dev-user|devUser)",
            re.MULTILINE,
        ),
        "severity": "CRITICAL",
        "message": "Client-controlled dev-user authentication marker detected. Do not trust browser-supplied user identity for server authorization. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "state-changing-fetch-without-csrf-token",
        "pattern": re.compile(
            r"(?is)\bfetch\s*\([^)]*method\s*:\s*[\"'](?:POST|PUT|PATCH|DELETE)[\"'](?:(?!csrf|xsrf).){0,300}\)",
        ),
        "severity": "WARNING",
        "message": "State-changing browser request has no nearby CSRF/XSRF token marker. Confirm SameSite cookie policy or token validation on the server. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "http-exception-chains-internal-error",
        "pattern": re.compile(
            r"raise\s+HTTPException\s*\([^)]*\)\s+from\s+exc",
            re.MULTILINE,
        ),
        "severity": "WARNING",
        "message": "HTTPException is chained from an internal exception. Avoid leaking implementation details in API error responses. [OWASP A05:2021 - Security Misconfiguration]",
        "extensions": [".py"],
    },
    {
        "id": "python-subprocess-user-controlled-args",
        "pattern": re.compile(
            r"(?is)subprocess\.(?:run|Popen|call|check_call|check_output)\s*\(\s*\[[^\]]{0,500}\b(?:source_path|input_path|filename|target_bytes|silence_noise)\b"
        ),
        "severity": "HIGH",
        "message": "Subprocess argument list includes high-risk user-controlled media or filename parameters. Validate each argument with strict allowlists and bounds before invoking external tools. [OWASP A03:2021 - Injection]",
        "extensions": [".py"],
    },
    {
        "id": "python-target-bytes-missing-upper-bound",
        "pattern": re.compile(
            r"(?is)\btarget_bytes\b(?:(?!\btarget_bytes\s*[<>]=?\s*(?:MAX_|max_|[0-9])).){0,500}\bif\s+target_bytes\s*<=\s*0\s*:"
        ),
        "severity": "HIGH",
        "message": "target_bytes is checked only for a lower bound. Add a server-side upper bound to prevent resource exhaustion in media processing. [OWASP A04:2021 - Insecure Design]",
        "extensions": [".py"],
    },
    {
        "id": "hardcoded-api-credential",
        "pattern": re.compile(
            r'(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key)\s*[=:]\s*["\x27][^"\x27\s]{8,}["\x27]',
            re.MULTILINE,
        ),
        "severity": "CRITICAL",
        "message": "Hardcoded API credential detected. Move credentials to secret storage and rotate any committed value. [OWASP A07:2021 - Identification and Authentication Failures]",
        "extensions": None,
    },
    {
        "id": "fastapi-state-changing-route-without-auth",
        "pattern": re.compile(
            r"(?is)@(?:app|router)\.(?:post|put|patch|delete)\s*\([^)]*\)\s*(?:async\s+)?def\s+\w+\s*\((?:(?!Depends|Security|current_user|require_auth|get_current_user|auth).){0,500}\)\s*:",
        ),
        "severity": "HIGH",
        "message": "State-changing FastAPI route has no nearby authentication dependency marker. Require authentication and server-side authorization before mutating state. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".py"],
    },
    {
        "id": "pydantic-bounding-box-unconstrained",
        "pattern": re.compile(
            r"(?is)class\s+\w*BoundingBox\w*\s*\([^)]*BaseModel[^)]*\)\s*:(?:(?!\nclass\s).){0,800}\b(?:x|y|width|height)\s*:\s*(?:float|int)\b(?:(?!Field\s*\(|ge\s*=|le\s*=).){0,800}\b(?:x|y|width|height)\s*:\s*(?:float|int)\b"
        ),
        "severity": "HIGH",
        "message": "Bounding box schema fields are unconstrained numeric values. Add min/max bounds to reject invalid coordinates before document processing. [OWASP A04:2021 - Insecure Design]",
        "extensions": [".py"],
    },
    {
        "id": "pydantic-unbounded-nested-list",
        "pattern": re.compile(
            r"(?is)class\s+\w+\s*\([^)]*BaseModel[^)]*\)\s*:(?:(?!\nclass\s).){0,800}\b\w+\s*:\s*(?:list|List)\s*\[\s*(?:list|List)\s*\["
        ),
        "severity": "HIGH",
        "message": "Pydantic model accepts nested lists without an obvious size or depth bound. Add max_length/depth validation for untrusted recursive structures. [OWASP A04:2021 - Insecure Design]",
        "extensions": [".py"],
    },
    {
        "id": "python-absolute-path-traversal-check-missing",
        "pattern": re.compile(
            r"(?is)Path\s*\([^)]*\)(?:(?!is_absolute).){0,600}[\"']\.\.[\"']\s+in\s+\w+\.parts"
        ),
        "severity": "HIGH",
        "message": "Path validation checks '..' parts but does not reject absolute paths nearby. Reject absolute paths and verify resolved paths stay under the allowed root. [OWASP A01:2021 - Broken Access Control]",
        "extensions": [".py"],
    },
    {
        "id": "python-requests-verify-false",
        "pattern": re.compile(
            r"(?is)\b(?:requests|httpx)\.(?:request|get|post|put|patch|delete)\s*\((?:(?!\n\s*\)).){0,500}verify\s*=\s*False"
        ),
        "severity": "HIGH",
        "message": "HTTP client disables TLS certificate verification. Keep verification enabled or pin a trusted CA bundle. [CWE-295 - Improper Certificate Validation]",
        "extensions": [".py"],
    },
    {
        "id": "python-tempfile-mktemp",
        "pattern": re.compile(r"\btempfile\.mktemp\s*\(", re.MULTILINE),
        "severity": "HIGH",
        "message": "tempfile.mktemp creates predictable names without opening the file atomically. Use NamedTemporaryFile or mkstemp. [CWE-377 - Insecure Temporary File]",
        "extensions": [".py"],
    },
    {
        "id": "python-flask-debug-true",
        "pattern": re.compile(
            r"(?is)\bapp\.run\s*\((?:(?!\n\s*\)).){0,300}debug\s*=\s*True|\bDEBUG\s*=\s*True"
        ),
        "severity": "HIGH",
        "message": "Debug mode is enabled in application code. Disable active debug code before deployment. [CWE-489 - Active Debug Code]",
        "extensions": [".py"],
    },
    {
        "id": "python-jinja-autoescape-disabled",
        "pattern": re.compile(
            r"(?is)\b(?:jinja2\.)?Environment\s*\((?:(?!\n\s*\)).){0,500}autoescape\s*=\s*False"
        ),
        "severity": "HIGH",
        "message": "Jinja2 autoescaping is disabled. Keep autoescape enabled for HTML templates to reduce XSS risk. [CWE-79 - Cross-site Scripting]",
        "extensions": [".py"],
    },
    {
        "id": "python-django-csrf-exempt",
        "pattern": re.compile(r"@csrf_exempt\b", re.MULTILINE),
        "severity": "HIGH",
        "message": "Django CSRF protection is explicitly disabled on a view. Require CSRF protection or document a safe non-browser authentication boundary. [CWE-352 - Cross-Site Request Forgery]",
        "extensions": [".py"],
    },
    {
        "id": "node-tls-validation-disabled",
        "pattern": re.compile(
            r"(?i)(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']0[\"']|rejectUnauthorized\s*:\s*false)"
        ),
        "severity": "HIGH",
        "message": "Node.js TLS certificate validation is disabled. Keep certificate validation enabled in production paths. [CWE-295 - Improper Certificate Validation]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "node-jwt-none-algorithm",
        "pattern": re.compile(
            r"(?is)\bjwt\.(?:verify|sign)\s*\((?:(?!\n\s*\)).){0,700}(?:algorithms?\s*:\s*\[[^\]]*[\"']none[\"']|algorithm\s*:\s*[\"']none[\"'])"
        ),
        "severity": "CRITICAL",
        "message": "JWT verification or signing allows the none algorithm. Pin expected algorithms and reject unsigned tokens. [CWE-347 - Improper Verification of Cryptographic Signature]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "node-cors-wildcard-with-credentials",
        "pattern": re.compile(
            r"(?is)\bcors\s*\(\s*\{(?:(?!\}\s*\)).){0,500}origin\s*:\s*[\"']\*[\"'](?:(?!\}\s*\)).){0,500}credentials\s*:\s*true"
        ),
        "severity": "HIGH",
        "message": "CORS allows every origin while credentials are enabled. Use an explicit allowlist for credentialed requests. [CWE-942 - Permissive Cross-domain Policy]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "node-helmet-csp-disabled",
        "pattern": re.compile(
            r"(?is)\bhelmet\s*\(\s*\{(?:(?!\}\s*\)).){0,500}contentSecurityPolicy\s*:\s*false"
        ),
        "severity": "HIGH",
        "message": "Helmet Content-Security-Policy is disabled. Keep CSP enabled or configure a strict policy. [CWE-693 - Protection Mechanism Failure]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "node-clickjacking-protection-disabled",
        "pattern": re.compile(
            r"(?is)(?:\bhelmet\s*\(\s*\{(?:(?!\}\s*\)).){0,500}(?:frameguard|xFrameOptions)\s*:\s*false|X-Frame-Options[\"']?\s*,\s*[\"']ALLOWALL[\"'])"
        ),
        "severity": "HIGH",
        "message": "Clickjacking protection is disabled. Use deny/sameorigin frame controls unless embedding is explicitly required. [CWE-1021 - Improper Restriction of Rendered UI Layers]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "express-reflected-input-send",
        "pattern": re.compile(
            r"(?is)\bres\.(?:send|write|end)\s*\((?:(?!sanitize|escape|encode).){0,300}\breq\.(?:query|params|body)\b"
        ),
        "severity": "HIGH",
        "message": "Express response sends request-controlled input without a nearby escaping marker. Encode output or render through a safe template context. [CWE-79 - Cross-site Scripting]",
        "extensions": [".ts", ".tsx", ".js", ".jsx"],
    },
    {
        "id": "java-spring-csrf-disabled",
        "pattern": re.compile(
            r"(?is)\.csrf\s*\(\s*\)\s*\.disable\s*\(|\.csrf\s*\(\s*\w+\s*->\s*\w+\.disable\s*\(\s*\)\s*\)|\.csrf\s*\(\s*AbstractHttpConfigurer\s*::\s*disable\s*\)"
        ),
        "severity": "HIGH",
        "message": "Spring CSRF protection is disabled. Keep CSRF enabled for browser-reachable state-changing routes or document a non-browser-only boundary. [CWE-352 - Cross-Site Request Forgery]",
        "extensions": [".java"],
    },
    {
        "id": "java-hostname-verifier-allow-all",
        "pattern": re.compile(
            r"(?is)(?:setHostnameVerifier\s*\([^)]*->\s*true|HostnameVerifier\b(?:(?!\n\s*\n).){0,800}\breturn\s+true\s*;)"
        ),
        "severity": "HIGH",
        "message": "Hostname verification accepts every host. Keep TLS hostname verification enabled to prevent machine-in-the-middle attacks. [CWE-295 - Improper Certificate Validation]",
        "extensions": [".java"],
    },
    {
        "id": "java-cookie-secure-false",
        "pattern": re.compile(r"\.setSecure\s*\(\s*false\s*\)", re.MULTILINE),
        "severity": "HIGH",
        "message": "Cookie Secure flag is explicitly disabled. Session and auth cookies should be restricted to HTTPS transport. [CWE-614 - Sensitive Cookie in HTTPS Session Without Secure Attribute]",
        "extensions": [".java"],
    },
    {
        "id": "java-jwt-none-algorithm",
        "pattern": re.compile(r"\bAlgorithm\.none\s*\(", re.MULTILINE),
        "severity": "CRITICAL",
        "message": "JWT code uses the none algorithm. Require a signed algorithm and validate issuer, audience, expiry, and key id. [CWE-347 - Improper Verification of Cryptographic Signature]",
        "extensions": [".java"],
    },
    {
        "id": "java-objectinputstream-deserialization",
        "pattern": re.compile(r"new\s+ObjectInputStream\s*\(", re.MULTILINE),
        "severity": "HIGH",
        "message": "ObjectInputStream deserialization detected. Do not deserialize untrusted data without strict type allowlists and integrity controls. [CWE-502 - Deserialization of Untrusted Data]",
        "extensions": [".java"],
    },
    {
        "id": "hardcoded-password",
        "pattern": re.compile(
            r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\x27][^"\x27\s]{6,}["\x27]'
        ),
        "severity": "HIGH",
        "message": "Possible hardcoded password detected. [OWASP A07:2021 - Identification and Authentication Failures]",
        "extensions": None,
    },
]

LANGUAGE_EXTENSIONS = {
    "javascript": [".js", ".jsx", ".mjs", ".cjs"],
    "typescript": [".ts", ".tsx", ".mts", ".cts"],
    "java": [".java"],
    "python": [".py"],
    "web": [".html", ".htm"],
}

LANGUAGE_BY_EXTENSION = {
    extension: language
    for language, extensions in LANGUAGE_EXTENSIONS.items()
    for extension in extensions
}


def _unquote_rule_scalar(value: str) -> str:
    """Return a simple YAML scalar value from the controlled rule files."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        quote = value[0]
        value = value[1:-1]
        if quote == "'":
            value = value.replace("''", "'")
    return value


def _parse_inline_list(value: str):
    """Parse the `[a, b]` lists used by scanner/rules/*.yml."""
    value = value.strip()
    if not (value.startswith("[") and value.endswith("]")):
        return []
    inner = value[1:-1].strip()
    if not inner:
        return []
    return [_unquote_rule_scalar(item) for item in inner.split(",")]


def _extensions_for_languages(languages):
    """Map YAML rule languages to file extensions for the regex scanner."""
    if not languages or "generic" in languages:
        return None

    extensions = []
    for language in languages:
        extensions.extend(LANGUAGE_EXTENSIONS.get(language, []))
    return sorted(set(extensions)) or None


def _parse_yaml_regex_rules(text: str, origin: str = "<rules>"):
    """Parse the supported pattern-regex subset of AppGuardrail rule YAML."""
    parsed_rules = []
    current = None
    in_message = False
    path_mode = None

    def finish_rule():
        if not current:
            return
        message = "\n".join(current.pop("message_lines", [])).strip()
        current["message"] = message or f"Rule {current['id']} matched."
        parsed_rules.append(current.copy())

    for raw_line in text.splitlines():
        if raw_line.startswith("  - id: "):
            finish_rule()
            current = {
                "id": _unquote_rule_scalar(raw_line.split(":", 1)[1]),
                "origin": origin,
                "regexes": [],
                "languages": [],
                "message_lines": [],
                "include_paths": [],
                "exclude_paths": [],
                "severity": "WARNING",
            }
            in_message = False
            path_mode = None
            continue

        if current is None:
            continue

        if in_message:
            if raw_line.startswith("      ") or not raw_line.strip():
                current["message_lines"].append(
                    raw_line[6:] if raw_line.startswith("      ") else ""
                )
                continue
            in_message = False

        stripped = raw_line.strip()
        if raw_line.startswith("    message: |"):
            in_message = True
            path_mode = None
            continue
        if raw_line.startswith("    severity: "):
            current["severity"] = _unquote_rule_scalar(
                raw_line.split(":", 1)[1]
            ).upper()
            path_mode = None
            continue
        if raw_line.startswith("    languages: "):
            current["languages"] = _parse_inline_list(raw_line.split(":", 1)[1])
            path_mode = None
            continue
        if raw_line.startswith("      - pattern-regex: "):
            current["regexes"].append(
                _unquote_rule_scalar(raw_line.split("pattern-regex:", 1)[1])
            )
            path_mode = None
            continue
        if stripped == "include:":
            path_mode = "include_paths"
            continue
        if stripped == "exclude:":
            path_mode = "exclude_paths"
            continue
        if path_mode and raw_line.startswith("        - "):
            current[path_mode].append(_unquote_rule_scalar(raw_line.split("- ", 1)[1]))

    finish_rule()
    return parsed_rules


def _compile_yaml_regex_rule(rule):
    """Build runtime regex scanner rules from one parsed YAML rule."""
    compiled_rules = []
    extensions = _extensions_for_languages(rule.get("languages") or [])
    for regex in rule.get("regexes") or []:
        try:
            pattern = re.compile(regex, re.MULTILINE)
        except re.error:
            continue
        compiled_rules.append(
            {
                "id": rule["id"],
                "pattern": pattern,
                "severity": rule.get("severity", "WARNING"),
                "message": rule.get("message") or f"Rule {rule['id']} matched.",
                "extensions": extensions,
                "include_paths": rule.get("include_paths") or [],
                "exclude_paths": rule.get("exclude_paths") or [],
            }
        )
    return compiled_rules


def _load_packaged_regex_rules():
    """Load supported regex rules from packaged scanner/rules/*.yml files."""
    loaded = []
    try:
        rule_files = sorted(resources.files("scanner.rules").iterdir())
    except (FileNotFoundError, ModuleNotFoundError):
        return loaded

    for rule_file in rule_files:
        if rule_file.suffix not in {".yml", ".yaml"}:
            continue
        try:
            text = rule_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for rule in _parse_yaml_regex_rules(text, origin=rule_file.name):
            loaded.extend(_compile_yaml_regex_rule(rule))
    return loaded


SCAN_RULES.extend(_load_packaged_regex_rules())

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".next",
    "dist",
    "build",
    ".cache",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".env",
    "coverage",
}

SECURITY_HIDDEN_DIRS = {
    ".github",
    ".vercel",
    ".netlify",
    ".supabase",
    ".firebase",
    ".well-known",
    ".config",
}

SKIP_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".mp3",
    ".zip",
    ".tar",
    ".gz",
    ".lock",
    ".map",
    ".log",
}

NON_BLOCKING_CONTEXTS = {"doc", "test", "example", "scanner-fixture"}
DEPLOY_BLOCKING_SEVERITIES = {"CRITICAL", "HIGH"}

# ---------------------------------------------------------------------------
# Review prompt templates
# ---------------------------------------------------------------------------

REVIEW_PROMPT_BASE = """\
Please perform a security review of this codebase. Focus on vulnerabilities
common in AI-generated web applications.

Review the following areas:

1. **Authentication**: Are there API routes missing auth checks?
2. **Authorization**: Is resource ownership verified server-side for every endpoint?
3. **Secrets**: Are there hardcoded secrets or NEXT_PUBLIC_ on sensitive vars?
4. **Input Validation**: Is user input validated server-side before database operations?
5. **CORS & Headers**: Is CORS restricted? Are security headers configured?
6. **AI Patterns**: Are there TODO comments that defer security checks?
"""

REVIEW_PROMPT_SUPABASE = """\
7. **Supabase RLS**: Is Row Level Security enabled on all user-data tables?
   Do policies use auth.uid() correctly? Is service_role used client-side?
8. **Supabase Auth**: Is getUser() used server-side (not getSession())?
"""

REVIEW_PROMPT_FIREBASE = """\
7. **Firebase Rules**: Are Firestore/Storage rules allowing unrestricted access?
   Is Firebase Admin SDK used only server-side?
"""

REVIEW_PROMPT_STRIPE = """\
9. **Stripe**: Is webhook signature verified with constructEvent?
   Are prices fetched server-side, not from the client? Is billing portal behind auth?
"""

REVIEW_PROMPT_NEXTJS = """\
Stack context: Next.js application.
- Check App Router API routes (app/api/) and server actions for auth gaps.
- Check next.config.js for security headers.
- Verify no secrets use NEXT_PUBLIC_ prefix.
"""

REVIEW_PROMPT_FOOTER = """\

For each issue found, provide:
1. File and location
2. Vulnerability description
3. Risk if exploited
4. Specific code fix
5. Verification test
"""


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------


def cmd_init(args):
    """Install security rules into the project."""
    tool = getattr(args, "tool", "auto") or "auto"
    stack = getattr(args, "stack", None)
    project_root = Path(".").resolve()

    installed = []
    skipped = []

    tool_configs = {
        "cursor": {
            "path": Path(".cursor") / "rules" / "appguardrail.md",
            "content": RULES_CURSOR,
        },
        "codex": {
            "path": Path("AGENTS.md"),
            "content": RULES_CODEX,
            "append_marker": "AppGuardrail",
        },
        "copilot": {
            "path": Path(".github") / "copilot-instructions.md",
            "content": RULES_COPILOT,
            "append_marker": "AppGuardrail",
        },
        "claude-code": {
            "path": Path("CLAUDE.md"),
            "content": RULES_CLAUDE,
            "append_marker": "AppGuardrail",
        },
        "windsurf": {
            "path": Path(".windsurf") / "rules" / "appguardrail.md",
            "content": RULES_WINDSURF,
        },
        "lovable": {
            "path": Path("LOVABLE_SECURITY_CHECKLIST.md"),
            "content": RULES_LOVABLE,
        },
    }
    tool_groups = {
        "auto": ["codex", "copilot", "claude-code", "cursor", "windsurf"],
    }

    selected_tools = tool_groups.get(tool, [tool])

    unknown_tools = [
        selected for selected in selected_tools if selected not in tool_configs
    ]
    if unknown_tools:
        print(f"❌ Error: Unknown tool '{tool}'", file=sys.stderr)
        print(
            f"💡 Hint: Supported tools are {', '.join([*tool_groups.keys(), *tool_configs.keys()])}",
            file=sys.stderr,
        )
        sys.exit(1)

    for selected_tool in selected_tools:
        config = tool_configs[selected_tool]
        if config.get("shared_only"):
            continue

        target_file = project_root / config["path"]

        # SECURITY: Prevent Arbitrary File Write via symlink path traversal
        if not target_file.resolve().is_relative_to(project_root):
            print(
                f"❌ Error: Target path {target_file} escapes the project root. Aborting.",
                file=sys.stderr,
            )
            print(
                "💡 Hint: Ensure the target file or its symlinks do not point outside the repository.",
                file=sys.stderr,
            )
            sys.exit(1)

        target_file.parent.mkdir(parents=True, exist_ok=True)
        if target_file.is_symlink():
            target_file.unlink()

        if "append_marker" in config and target_file.exists():
            existing = target_file.read_text()
            if config["append_marker"] not in existing:
                target_file.write_text(existing + "\n\n" + config["content"])
                installed.append(f"{config['path']} (appended)")
            else:
                skipped.append(str(config["path"]))
        else:
            target_file.write_text(config["content"])
            installed.append(str(config["path"]))
    # Always create the checklist
    checklist_file = project_root / "APPGUARDRAIL_CHECKLIST.md"

    # SECURITY: Prevent Arbitrary File Write via symlink path traversal
    if not checklist_file.resolve().is_relative_to(project_root):
        print(
            f"❌ Error: Checklist path {checklist_file} escapes the project root. Aborting.",
            file=sys.stderr,
        )
        print(
            "💡 Hint: Ensure the checklist file or its symlinks do not point outside the repository.",
            file=sys.stderr,
        )
        sys.exit(1)

    if checklist_file.is_symlink():
        checklist_file.unlink()
    if not checklist_file.exists():
        checklist_file.write_text(CHECKLIST_TEMPLATE)
        installed.append("APPGUARDRAIL_CHECKLIST.md")
    else:
        skipped.append("APPGUARDRAIL_CHECKLIST.md")

    if stack and "supabase" in stack:
        _print_supabase_reminder()

    print("\n✅ AppGuardrail initialized successfully!\n")
    if installed:
        print("✨ Created/updated files:")
        for f in installed:
            print(f"  {f}")
        print()

    if skipped:
        print("⏭️  Skipped (already configured):")
        for f in skipped:
            print(f"  {f}")
        print()

    print("🚀 Next steps:")
    print("  1. Review the installed rules and customize for your project")
    print("  2. Run 'appguardrail scan .' to check for existing issues")
    print("  3. Check APPGUARDRAIL_CHECKLIST.md before deploying")
    print()


def _print_supabase_reminder():
    """Print extra operational reminders for Supabase-backed projects."""
    print("\n💡 Supabase stack detected. Quick reminders:")
    print("  - Enable RLS on every user-data table")
    print("  - Use getUser() not getSession() on the server")
    print("  - Keep SUPABASE_SERVICE_ROLE_KEY server-side only")
    print()


def _detect_scan_languages(files):
    """Return language axes found in a scan target without requiring a profile."""
    languages = set()
    for file_path in files:
        language = LANGUAGE_BY_EXTENSION.get(file_path.suffix.lower())
        if language:
            languages.add(language)
    return languages


def _external_tool_available(name: str, version_args=("--version",)):
    """Return a runnable external tool path, or None for missing/broken tools."""
    executable = shutil.which(name)
    if not executable:
        return None
    try:
        process = subprocess.run(
            [executable, *version_args],
            shell=False,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if process.returncode != 0:
        return None
    return executable


def cmd_scan(args):
    """Run a lightweight security scan."""
    scan_arg = Path(getattr(args, "path", ".") or ".")
    scan_path = scan_arg.resolve()
    run_trivy = getattr(args, "trivy", False)
    external_mode = getattr(args, "external", "off")
    force_bandit = getattr(args, "bandit", False)
    force_ruff = getattr(args, "ruff", False)
    force_semgrep = getattr(args, "semgrep", False)
    semgrep_config = getattr(args, "semgrep_config", None) or os.environ.get(
        "APPGUARDRAIL_SEMGREP_CONFIG", "auto"
    )
    zap_baseline_url = getattr(args, "zap_baseline", None) or os.environ.get(
        "APPGUARDRAIL_TARGET_URL"
    )
    force_zap = bool(getattr(args, "zap_baseline", None))
    run_codegraph = getattr(args, "codegraph", False)

    if not scan_arg.exists():
        print(f"❌ Error: Path does not exist: {scan_path}", file=sys.stderr)
        print(
            "💡 Hint: Check if the path is correct or if you are in the right directory.",
            file=sys.stderr,
        )
        sys.exit(1)

    if scan_arg.is_symlink():
        print(f"Skipping symlink path: {scan_arg}")
        return 0

    print(f"\n🔍 AppGuardrail scanning: {scan_path}\n")

    if run_codegraph:
        print("🧭 CodeGraph enabled: initializing or syncing structural index\n")
        try:
            status = _run_codegraph_index(scan_path)
        except RuntimeError as exc:
            print(f"❌ Error: {exc}", file=sys.stderr)
            print(
                "💡 Hint: Install the CodeGraph CLI or run without --codegraph.",
                file=sys.stderr,
            )
            return 1
        if status:
            print(status)
            print()

    findings = []
    files_scanned = 0

    if scan_path.is_file():
        files_to_scan = [scan_path]
    else:
        files_to_scan = list(_collect_files(scan_path))

    languages = _detect_scan_languages(files_to_scan)
    if languages:
        print(f"🧩 Detected language axes: {', '.join(sorted(languages))}\n")

    for file_path in files_to_scan:
        files_scanned += 1
        file_findings = _scan_file(file_path, scan_path)
        findings.extend(file_findings)

    auto_external = external_mode == "auto"
    auto_bandit = (
        auto_external and "python" in languages and _external_tool_available("bandit")
    )
    auto_ruff = (
        auto_external and "python" in languages and _external_tool_available("ruff")
    )
    auto_semgrep = (
        auto_external
        and bool(languages & {"java", "javascript", "python", "typescript", "web"})
        and _external_tool_available("semgrep")
    )
    auto_zap = bool(zap_baseline_url) and (
        auto_external and _external_tool_available("zap-baseline.py", ("-h",))
    )
    run_bandit = force_bandit or auto_bandit
    run_ruff = force_ruff or auto_ruff
    run_semgrep = force_semgrep or auto_semgrep
    run_zap = bool(zap_baseline_url) and (force_zap or auto_zap)

    if run_trivy:
        print("🔎 Trivy FS enabled: vuln, secret, misconfig\n")
        try:
            findings.extend(_run_trivy_fs(scan_path))
        except RuntimeError as exc:
            print(f"❌ Error: {exc}", file=sys.stderr)
            print(
                "💡 Hint: Ensure Trivy is installed and running correctly, or run without --trivy.",
                file=sys.stderr,
            )
            return 1

    if run_bandit:
        print("🐍 Bandit enabled: Python SAST\n")
        try:
            findings.extend(_run_bandit_scan(scan_path))
        except RuntimeError as exc:
            if auto_bandit and not force_bandit:
                print(f"⚠️  Skipping Bandit auto integration: {exc}\n")
            else:
                print(f"❌ Error: {exc}", file=sys.stderr)
                print(
                    "💡 Hint: Install Bandit or run without --bandit.",
                    file=sys.stderr,
                )
                return 1

    if run_ruff:
        print("🐍 Ruff security rules enabled: select S\n")
        try:
            findings.extend(_run_ruff_security_scan(scan_path))
        except RuntimeError as exc:
            if auto_ruff and not force_ruff:
                print(f"⚠️  Skipping Ruff auto integration: {exc}\n")
            else:
                print(f"❌ Error: {exc}", file=sys.stderr)
                print(
                    "💡 Hint: Install Ruff or run without --ruff.",
                    file=sys.stderr,
                )
                return 1

    if run_semgrep:
        print(f"🔎 Semgrep enabled: config {semgrep_config}\n")
        try:
            findings.extend(_run_semgrep_scan(scan_path, semgrep_config))
        except RuntimeError as exc:
            if auto_semgrep and not force_semgrep:
                print(f"⚠️  Skipping Semgrep auto integration: {exc}\n")
            else:
                print(f"❌ Error: {exc}", file=sys.stderr)
                print(
                    "💡 Hint: Install Semgrep correctly or run with --external off.",
                    file=sys.stderr,
                )
                return 1

    if run_zap:
        print(f"🌐 OWASP ZAP baseline enabled: {zap_baseline_url}\n")
        try:
            findings.extend(_run_zap_baseline(zap_baseline_url))
        except RuntimeError as exc:
            if auto_zap and not force_zap:
                print(f"⚠️  Skipping ZAP auto integration: {exc}\n")
            else:
                print(f"❌ Error: {exc}", file=sys.stderr)
                print(
                    "💡 Hint: Install zap-baseline.py or run without --zap-baseline.",
                    file=sys.stderr,
                )
                return 1

    _print_scan_results(findings, files_scanned)
    if files_scanned == 0:
        return 1
    return 1 if any(_is_deploy_blocking(f) for f in findings) else 0


def cmd_monitor(args):
    """Install a GitHub Actions workflow that runs AppGuardrail on changes."""
    project_root = Path(".").resolve()
    workflow_file = project_root / ".github" / "workflows" / "appguardrail-monitor.yml"

    if not workflow_file.resolve().is_relative_to(project_root):
        print(
            f"❌ Error: Monitor workflow path {workflow_file} escapes the project root. Aborting.",
            file=sys.stderr,
        )
        print(
            "💡 Hint: Ensure .github/workflows and its symlinks stay inside the repository.",
            file=sys.stderr,
        )
        return 1

    workflow_file.parent.mkdir(parents=True, exist_ok=True)
    if workflow_file.is_symlink():
        workflow_file.unlink()
    workflow_file.write_text(MONITOR_WORKFLOW)

    print("\n✅ AppGuardrail monitor workflow installed!\n")
    print(f"Created/updated: {workflow_file.relative_to(project_root)}")
    print()
    print(
        "This workflow runs `appguardrail scan .` on pull requests, pushes, and manual dispatches."
    )
    return 0


def cmd_hook(args):
    """Install a pre-commit hook to block commits with vulnerabilities."""
    project_root = Path(".").resolve()
    git_dir = project_root / ".git"
    run_codegraph = getattr(args, "codegraph", False)

    if not git_dir.is_dir():
        print("❌ Error: Not a git repository.", file=sys.stderr)
        print(
            "💡 Hint: Run 'git init' first to initialize a git repository.",
            file=sys.stderr,
        )
        return 1

    hooks_dir = git_dir / "hooks"
    # SECURITY: Prevent Arbitrary File Write via symlink path traversal
    if not hooks_dir.resolve().is_relative_to(project_root):
        print(
            f"❌ Error: Target path {hooks_dir} escapes the project root. Aborting.",
            file=sys.stderr,
        )
        print(
            "💡 Hint: Ensure your .git directory or hooks path is contained within the project.",
            file=sys.stderr,
        )
        return 1

    hooks_dir.mkdir(parents=True, exist_ok=True)
    pre_commit_file = hooks_dir / "pre-commit"

    if pre_commit_file.is_symlink():
        pre_commit_file.unlink()

    cli_path = shlex.quote(str(Path(__file__).resolve()))
    scan_flags = " --codegraph" if run_codegraph else ""
    hook_content = f"""#!/bin/sh
# AppGuardrail Pre-Commit Hook

echo "\\n🔍 Running AppGuardrail scan..."
APPGUARDRAIL_CLI={cli_path}

if command -v appguardrail >/dev/null 2>&1; then
    appguardrail scan{scan_flags} .
elif [ -f "$APPGUARDRAIL_CLI" ]; then
    python3 "$APPGUARDRAIL_CLI" scan{scan_flags} .
else
    echo "\\n❌ AppGuardrail CLI not found."
    echo "Install appguardrail or reinstall this hook from a trusted AppGuardrail checkout."
    exit 127
fi

if [ $? -ne 0 ]; then
    echo "\\n❌ AppGuardrail scan failed! Critical or high vulnerabilities found."
    echo "Please fix the issues or use '--no-verify' to bypass (not recommended)."
    exit 1
fi

echo "✅ AppGuardrail scan passed."
"""

    pre_commit_file.write_text(hook_content)
    pre_commit_file.chmod(pre_commit_file.stat().st_mode | stat.S_IEXEC)

    print(
        "\n✅ AppGuardrail pre-commit hook installed successfully at .git/hooks/pre-commit!\n"
    )
    hook_scan_command = f"appguardrail scan{scan_flags} ."
    print(
        f"This will run '{hook_scan_command}' before every commit and block commits if vulnerabilities are found."
    )
    if run_codegraph:
        print("CodeGraph mode is enabled for this hook.")
    return 0


# ⚡ Bolt: Cache applicable rules per file extension to avoid redundant list
# comprehensions and pre-extract the finditer method used in the tight loop.
_RULES_CACHE = {}
_LAST_SCAN_RULES_ID = None


def _get_applicable_rules(ext: str):
    """Return cached scanner rules that apply to a file extension."""
    global _LAST_SCAN_RULES_ID, _RULES_CACHE
    current_id = id(SCAN_RULES)
    if _LAST_SCAN_RULES_ID != current_id:
        _RULES_CACHE.clear()
        _LAST_SCAN_RULES_ID = current_id

    if ext not in _RULES_CACHE:
        _RULES_CACHE[ext] = [
            (
                rule["id"],
                rule["severity"],
                rule["message"],
                rule["pattern"].finditer,
                rule["pattern"].search,
                tuple(rule.get("include_paths") or ()),
                tuple(rule.get("exclude_paths") or ()),
            )
            for rule in SCAN_RULES
            if not rule["extensions"] or ext in rule["extensions"]
        ]
    return _RULES_CACHE[ext]


def _path_matches_glob(path: str, pattern: str) -> bool:
    """Match a normalized relative path against AppGuardrail rule globs."""
    path = path.replace("\\", "/")
    pattern = pattern.replace("\\", "/")
    if path.startswith("./"):
        path = path[2:]
    if pattern.startswith("./"):
        pattern = pattern[2:]
    if fnmatch.fnmatch(path, pattern):
        return True
    if pattern.startswith("**/") and fnmatch.fnmatch(path, pattern[3:]):
        return True
    return False


def _path_allowed_by_rule(path: str, include_paths, exclude_paths) -> bool:
    """Return whether a path passes optional YAML include/exclude filters."""
    if include_paths and not any(
        _path_matches_glob(path, glob) for glob in include_paths
    ):
        return False
    if exclude_paths and any(_path_matches_glob(path, glob) for glob in exclude_paths):
        return False
    return True


def _collect_files(base_path: Path):
    """Collect all scannable files, skipping unwanted directories."""
    # ⚡ Bolt: Optimize file traversal using os.scandir and os.path.splitext
    # This avoids expensive stat() calls by using cached directory attributes
    # and defers Path object creation until a valid file is found.
    # Impact: Significantly faster file discovery in large codebases.
    stack = [str(base_path)]
    while stack:
        current_dir = stack.pop()
        try:
            with os.scandir(current_dir) as it:
                dirs = []
                for entry in it:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name not in SKIP_DIRS and (
                                not entry.name.startswith(".")
                                or entry.name in SECURITY_HIDDEN_DIRS
                            ):
                                dirs.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            _, ext = os.path.splitext(entry.name)
                            if ext.lower() not in SKIP_EXTENSIONS:
                                yield Path(entry.path)
                    except (OSError, PermissionError):
                        continue
                stack.extend(reversed(dirs))
        except (OSError, PermissionError):
            pass


def _sanitize_terminal_output(text: str) -> str:
    """
    SECURITY: Prevent Terminal Output Injection / ANSI escape sequence injection
    that could hide scanner findings by removing or escaping non-printable characters.
    """
    if not isinstance(text, str):
        return text
    return "".join(c if c.isprintable() or c == "\t" else repr(c)[1:-1] for c in text)


_SENSITIVE_RULE_TOKENS = (
    "secret",
    "password",
    "token",
    "jwt",
    "database-url",
    "db-url",
    "dsn",
    "credential",
    "stripe",
    "openai",
    "supabase-service-role",
)
_REDACTED_SENSITIVE_SNIPPET = "[REDACTED: sensitive match suppressed]"


def _is_sensitive_rule(rule_id: str) -> bool:
    """Return whether a rule id is likely to expose secret material."""
    lowered = (rule_id or "").lower()
    return any(token in lowered for token in _SENSITIVE_RULE_TOKENS)


def _safe_snippet(rule_id: str, snippet: str, category: str) -> str:
    """Redact sensitive snippets and sanitize non-sensitive terminal output."""
    if category == "secrets" or _is_sensitive_rule(rule_id):
        return _REDACTED_SENSITIVE_SNIPPET
    return _sanitize_terminal_output(snippet)


def _finding_context(file_path: str, snippet: str = "") -> str:
    """Classify a finding path as app code, docs, tests, examples, or fixtures."""
    path = (file_path or "").replace("\\", "/").lstrip("./")
    snippet = (snippet or "").strip()
    if path == "README.md" or path.startswith(("docs/", "checklists/", "prompts/")):
        return "doc"
    if path.startswith("tests/") or "/tests/" in path:
        return "test"
    if path.startswith("examples/"):
        return "example"
    if path.startswith("scanner/rules/"):
        return "scanner-fixture"
    if path == "scanner/cli/appguardrail.py" and (
        snippet.startswith(('"id":', '"message":', '"pattern":', "r'", 'r"'))
        or "TODO comments that defer" in snippet
    ):
        return "scanner-fixture"
    return "app-code"


def _finding_category(rule_id: str) -> str:
    """Map a rule id to a stable finding category."""
    rule = (rule_id or "").lower()
    if "cve-" in rule or "vulnerability" in rule:
        return "dependency"
    if "jwt-decode" in rule:
        return "authz"
    if any(
        token in rule
        for token in (
            "secret",
            "jwt",
            "password",
            "database-url",
            "credential",
            "api-key",
            "token",
            "openai",
        )
    ):
        return "secrets"
    if "stripe" in rule or "webhook" in rule:
        return "payment"
    if "firebase" in rule or "supabase" in rule or "storage" in rule:
        return "storage"
    if any(
        token in rule for token in ("auth", "session", "admin", "route-without-auth")
    ):
        return "authz"
    if any(
        token in rule
        for token in ("eval", "sql", "command", "subprocess", "path-traversal")
    ):
        return "injection"
    return "misconfig"


def _confidence(rule_id: str) -> str:
    """Return a conservative confidence label for a rule id."""
    return "medium" if "todo" in (rule_id or "").lower() else "high"


def _build_finding(
    source, rule_id, severity, message, file, line, snippet, category=None
):
    """Build the normalized finding dictionary emitted by scan providers."""
    context = _finding_context(file, snippet)
    category = category or _finding_category(rule_id)
    return {
        "rule_id": rule_id,
        "severity": severity,
        "message": message,
        "file": file,
        "line": line,
        "snippet": _safe_snippet(rule_id, snippet, category),
        "source": source,
        "category": category,
        "confidence": _confidence(rule_id),
        "context": context,
        "fix_prompt": f"Fix {rule_id}: {message}",
        "verification": f"Re-run `appguardrail scan` and verify {file}:{line} no longer reports this finding.",
    }


def _is_deploy_blocking(finding: dict) -> bool:
    """Return whether a finding should fail the deploy gate."""
    return (
        finding.get("severity") in DEPLOY_BLOCKING_SEVERITIES
        and finding.get("context", "app-code") not in NON_BLOCKING_CONTEXTS
    )


_TRIVY_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "WARNING",
    "LOW": "INFO",
    "UNKNOWN": "INFO",
}


def _trivy_severity(severity: str) -> str:
    """Translate Trivy severity values into AppGuardrail severities."""
    return _TRIVY_SEVERITY_MAP.get((severity or "UNKNOWN").upper(), "INFO")


def _trivy_line(item: dict) -> int:
    """Extract the best source line from a Trivy result item."""
    metadata = item.get("CauseMetadata") or {}
    return item.get("StartLine") or metadata.get("StartLine") or 1


def _trivy_target(target: str, base_path: Path) -> str:
    """Normalize a Trivy target path relative to the scan base when possible."""
    if not target:
        return str(base_path)
    try:
        path = Path(target)
        if path.is_absolute():
            root = base_path if base_path.is_dir() else base_path.parent
            return str(path.relative_to(root))
    except ValueError:
        pass
    return target


def _trivy_findings(report: dict, base_path: Path):
    """Convert a Trivy JSON report into AppGuardrail finding dictionaries."""
    findings = []
    for result in report.get("Results") or []:
        target = _sanitize_terminal_output(
            _trivy_target(result.get("Target", ""), base_path)
        )

        for vuln in result.get("Vulnerabilities") or []:
            fixed = vuln.get("FixedVersion") or "no fixed version reported"
            findings.append(
                _build_finding(
                    "trivy",
                    f"trivy:{vuln.get('VulnerabilityID', 'vulnerability')}",
                    _trivy_severity(vuln.get("Severity")),
                    f"Trivy vulnerability in {vuln.get('PkgName', 'package')}: {vuln.get('Title') or vuln.get('VulnerabilityID', 'unknown vulnerability')}",
                    target,
                    1,
                    f"{vuln.get('PkgName', 'package')} {vuln.get('InstalledVersion', '')} -> {fixed}".strip(),
                    category="dependency",
                )
            )

        for misconfig in result.get("Misconfigurations") or []:
            findings.append(
                _build_finding(
                    "trivy",
                    f"trivy:{misconfig.get('ID', 'misconfiguration')}",
                    _trivy_severity(misconfig.get("Severity")),
                    f"Trivy misconfiguration: {misconfig.get('Title') or misconfig.get('Message') or misconfig.get('ID', 'misconfiguration')}",
                    target,
                    _trivy_line(misconfig),
                    misconfig.get("Message") or misconfig.get("Description") or "",
                    category="misconfig",
                )
            )

        for secret in result.get("Secrets") or []:
            findings.append(
                _build_finding(
                    "trivy",
                    f"trivy:{secret.get('RuleID', 'secret')}",
                    _trivy_severity(secret.get("Severity")),
                    f"Trivy secret finding: {secret.get('Title') or secret.get('Category') or secret.get('RuleID', 'secret')}",
                    target,
                    _trivy_line(secret),
                    "Trivy secret scanner matched this line; value suppressed.",
                    category="secrets",
                )
            )

    return findings


def _run_trivy_fs(scan_path: Path):
    """Run Trivy filesystem scanning and return normalized findings."""
    trivy = shutil.which("trivy")
    if not trivy:
        raise RuntimeError(
            "trivy executable not found. Install Trivy or run without --trivy."
        )

    try:
        process = subprocess.run(
            [
                trivy,
                "fs",
                "--quiet",
                "--format",
                "json",
                "--scanners",
                "vuln,secret,misconfig",
                "--exit-code",
                "0",
                "--no-progress",
                "--skip-version-check",
                str(scan_path),
            ],
            shell=False,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Trivy scan timed out.") from exc
    if process.returncode != 0:
        detail = (process.stderr or process.stdout).strip().splitlines()
        raise RuntimeError("Trivy scan failed" + (f": {detail[-1]}" if detail else "."))

    try:
        report = json.loads(process.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Trivy returned invalid JSON: {exc}") from exc

    return _trivy_findings(report, scan_path)


def _bandit_severity(severity: str) -> str:
    """Translate Bandit severity values into AppGuardrail severities."""
    return _TRIVY_SEVERITY_MAP.get((severity or "LOW").upper(), "INFO")


def _bandit_findings(report: dict, base_path: Path):
    """Convert a Bandit JSON report into AppGuardrail finding dictionaries."""
    findings = []
    for result in report.get("results") or []:
        test_id = result.get("test_id") or "bandit"
        filename = _sanitize_terminal_output(
            _trivy_target(result.get("filename", ""), base_path)
        )
        findings.append(
            _build_finding(
                "bandit",
                f"bandit:{test_id}",
                _bandit_severity(result.get("issue_severity")),
                result.get("issue_text") or result.get("test_name") or test_id,
                filename,
                result.get("line_number") or 1,
                result.get("code") or "",
            )
        )
    return findings


def _run_bandit_scan(scan_path: Path):
    """Run Bandit Python SAST and return normalized findings."""
    bandit = shutil.which("bandit")
    if not bandit:
        raise RuntimeError("bandit executable not found.")

    command = [bandit, "-f", "json", "-q"]
    if scan_path.is_dir():
        command.extend(["-r", str(scan_path)])
    else:
        command.append(str(scan_path))

    try:
        process = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Bandit scan timed out.") from exc

    if process.returncode not in {0, 1}:
        detail = (process.stderr or process.stdout).strip().splitlines()
        raise RuntimeError("Bandit scan failed" + (f": {detail[-1]}" if detail else "."))

    try:
        report = json.loads(process.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Bandit returned invalid JSON: {exc}") from exc

    return _bandit_findings(report, scan_path)


def _ruff_severity(code: str) -> str:
    """Translate Ruff security rule codes into AppGuardrail severities."""
    code = code or ""
    return "WARNING" if code in {"S101", "S104"} else "HIGH"


def _ruff_findings(report: list, base_path: Path):
    """Convert Ruff JSON diagnostics into AppGuardrail finding dictionaries."""
    findings = []
    for item in report or []:
        code = item.get("code") or "ruff"
        location = item.get("location") or {}
        filename = _sanitize_terminal_output(
            _trivy_target(item.get("filename", ""), base_path)
        )
        findings.append(
            _build_finding(
                "ruff",
                f"ruff:{code}",
                _ruff_severity(code),
                item.get("message") or code,
                filename,
                location.get("row") or 1,
                item.get("message") or code,
            )
        )
    return findings


def _run_ruff_security_scan(scan_path: Path):
    """Run Ruff's Bandit-compatible security rules and return findings."""
    ruff = shutil.which("ruff")
    if not ruff:
        raise RuntimeError("ruff executable not found.")

    try:
        process = subprocess.run(
            [
                ruff,
                "check",
                "--select",
                "S",
                "--output-format",
                "json",
                str(scan_path),
            ],
            shell=False,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Ruff security scan timed out.") from exc

    if process.returncode not in {0, 1}:
        detail = (process.stderr or process.stdout).strip().splitlines()
        raise RuntimeError(
            "Ruff security scan failed" + (f": {detail[-1]}" if detail else ".")
        )

    try:
        report = json.loads(process.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Ruff returned invalid JSON: {exc}") from exc

    return _ruff_findings(report, scan_path)


_SEMGREP_SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "WARNING",
    "INFO": "INFO",
    "INVENTORY": "INFO",
    "EXPERIMENT": "INFO",
}


def _semgrep_severity(severity: str) -> str:
    """Translate Semgrep severity values into AppGuardrail severities."""
    return _SEMGREP_SEVERITY_MAP.get((severity or "INFO").upper(), "INFO")


def _semgrep_findings(report: dict, base_path: Path):
    """Convert Semgrep JSON results into AppGuardrail finding dictionaries."""
    findings = []
    for item in report.get("results") or []:
        extra = item.get("extra") or {}
        start = item.get("start") or {}
        path = _sanitize_terminal_output(
            _trivy_target(item.get("path", ""), base_path)
        )
        check_id = item.get("check_id") or "semgrep"
        findings.append(
            _build_finding(
                "semgrep",
                f"semgrep:{check_id}",
                _semgrep_severity(extra.get("severity")),
                extra.get("message") or check_id,
                path,
                start.get("line") or 1,
                extra.get("lines") or extra.get("message") or check_id,
            )
        )
    return findings


def _run_semgrep_scan(scan_path: Path, config: str = "auto"):
    """Run Semgrep multi-language SAST and return normalized findings."""
    semgrep = shutil.which("semgrep")
    if not semgrep:
        raise RuntimeError("semgrep executable not found.")

    config = config or "auto"
    try:
        process = subprocess.run(
            [
                semgrep,
                "scan",
                "--config",
                config,
                "--json",
                str(scan_path),
            ],
            shell=False,
            capture_output=True,
            text=True,
            check=False,
            timeout=600,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Semgrep scan timed out.") from exc

    if process.returncode not in {0, 1}:
        detail = (process.stderr or process.stdout).strip().splitlines()
        raise RuntimeError(
            "Semgrep scan failed" + (f": {detail[-1]}" if detail else ".")
        )

    try:
        report = json.loads(process.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Semgrep returned invalid JSON: {exc}") from exc

    return _semgrep_findings(report, scan_path)


_ZAP_SEVERITY_MAP = {
    "HIGH": "HIGH",
    "MEDIUM": "WARNING",
    "LOW": "INFO",
    "INFORMATIONAL": "INFO",
}


def _zap_severity(risk: str) -> str:
    """Translate ZAP risk text into AppGuardrail severities."""
    risk_text = (risk or "INFO").split()[0].upper()
    return _ZAP_SEVERITY_MAP.get(risk_text, "INFO")


def _zap_findings(report: dict):
    """Convert an OWASP ZAP JSON report into AppGuardrail findings."""
    findings = []
    for site in report.get("site") or []:
        for alert in site.get("alerts") or []:
            instances = alert.get("instances") or [{}]
            for instance in instances:
                uri = instance.get("uri") or site.get("@name") or "zap-baseline"
                findings.append(
                    _build_finding(
                        "zap",
                        f"zap:{alert.get('pluginid', 'alert')}",
                        _zap_severity(alert.get("riskdesc") or alert.get("risk")),
                        alert.get("alert") or alert.get("name") or "ZAP alert",
                        _sanitize_terminal_output(uri),
                        1,
                        instance.get("evidence") or alert.get("desc") or "",
                        category="misconfig",
                    )
                )
    return findings


def _run_zap_baseline(target_url: str):
    """Run OWASP ZAP baseline scan against an explicit URL."""
    if not target_url or not re.match(r"^https?://", target_url):
        raise RuntimeError("--zap-baseline requires an http(s) URL.")
    zap = shutil.which("zap-baseline.py")
    if not zap:
        raise RuntimeError("zap-baseline.py executable not found.")

    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = Path(tmpdir) / "zap-baseline.json"
        try:
            process = subprocess.run(
                [zap, "-t", target_url, "-J", str(report_path), "-I"],
                shell=False,
                capture_output=True,
                text=True,
                check=False,
                timeout=900,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("ZAP baseline scan timed out.") from exc

        if process.returncode not in {0, 1, 2}:
            detail = (process.stderr or process.stdout).strip().splitlines()
            raise RuntimeError(
                "ZAP baseline scan failed" + (f": {detail[-1]}" if detail else ".")
            )

        try:
            report = json.loads(report_path.read_text(encoding="utf-8") or "{}")
        except OSError as exc:
            raise RuntimeError("ZAP baseline did not produce a JSON report.") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"ZAP baseline returned invalid JSON: {exc}") from exc

    return _zap_findings(report)


def _run_codegraph_command(command, cwd: Path, action: str):
    """Run an allowlisted CodeGraph command in a trusted working directory."""
    if not command:
        raise RuntimeError("CodeGraph command cannot be empty.")
    for arg in command:
        if not isinstance(arg, str):
            raise RuntimeError(
                f"CodeGraph command argument must be a string, got {type(arg).__name__}."
            )
        if not arg.isprintable():
            raise RuntimeError(
                "CodeGraph command argument contains control characters."
            )

    executable = Path(command[0]).name
    allowed_args = {("sync",), ("init", "-i"), ("status",)}
    if executable != "codegraph" or tuple(command[1:]) not in allowed_args:
        raise RuntimeError(f"Unsupported CodeGraph {action} command.")

    try:
        process = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"CodeGraph {action} timed out.") from exc
    if process.returncode != 0:
        detail = (process.stderr or process.stdout).strip().splitlines()
        suffix = f": {detail[-1]}" if detail else "."
        raise RuntimeError(f"CodeGraph {action} failed{suffix}")
    return (process.stdout or "").strip()


def _run_codegraph_index(scan_path: Path):
    """Initialize or sync the CodeGraph index for the scanned path."""
    codegraph = shutil.which("codegraph")
    if not codegraph:
        raise RuntimeError(
            "codegraph executable not found. Install CodeGraph before using --codegraph."
        )

    workdir = scan_path if scan_path.is_dir() else scan_path.parent
    if not workdir.is_dir():
        raise RuntimeError(f"CodeGraph workdir is not a directory: {workdir}")

    codegraph_dir = workdir / ".codegraph"
    if codegraph_dir.exists() and not codegraph_dir.is_dir():
        raise RuntimeError(
            f"CodeGraph path exists but is not a directory: {codegraph_dir}"
        )
    if codegraph_dir.is_dir():
        _run_codegraph_command([codegraph, "sync"], workdir, "sync")
    else:
        _run_codegraph_command([codegraph, "init", "-i"], workdir, "init")

    return _run_codegraph_command([codegraph, "status"], workdir, "status")


def _scan_file(file_path: Path, base_path: Path):
    """Scan a single file and return a list of findings."""
    findings = []

    # ⚡ Bolt: Hoist expensive relative_to base_path resolution outside of loops.
    # Path.is_dir() and Path.resolve() invoke stat() system calls. Doing this inside
    # the finding iteration loop for every match was causing massive I/O overhead.
    resolved_base_path = base_path if base_path.is_dir() else Path(".").resolve()

    # ⚡ Bolt: Optimize stat calls by using os.lstat instead of Path objects
    # Impact: Combines symlink, file type, and size checks into a single stat call
    try:
        st = os.lstat(file_path)
        # SECURITY: Prevent DoS by skipping special system files (e.g. FIFOs, devices)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            return findings
        # SECURITY: Prevent OOM by skipping extremely large files
        if st.st_size > 10 * 1024 * 1024:
            return findings
    except (OSError, PermissionError):
        return findings

    ext = file_path.suffix.lower()
    applicable_rules = _get_applicable_rules(ext)

    if not applicable_rules:
        return findings

    # ⚡ Bolt: Defer expensive Pathlib operations (like relative_to) and string
    # sanitization until a match is actually found. This avoids significant overhead
    # for the vast majority of files that have no vulnerabilities.
    rel_path_str = None
    rel_path_for_filters = None
    build_finding = _build_finding

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            if not content:
                return findings
            count_newlines = content.count
            find_newline = content.find
            rfind_newline = content.rfind

            for (
                rule_id,
                severity,
                message,
                finditer,
                search_method,
                include_paths,
                exclude_paths,
            ) in applicable_rules:
                if include_paths or exclude_paths:
                    if rel_path_for_filters is None:
                        try:
                            rel_path = file_path.relative_to(resolved_base_path)
                        except ValueError:
                            rel_path = (
                                file_path.name if base_path.is_file() else file_path
                            )
                        rel_path_for_filters = str(rel_path)
                    if not _path_allowed_by_rule(
                        rel_path_for_filters, include_paths, exclude_paths
                    ):
                        continue
                # ⚡ Bolt: Fast path rejection using pre-bound search method
                if not search_method(content):
                    continue

                for match in finditer(content):
                    if rel_path_str is None:
                        try:
                            rel_path = file_path.relative_to(resolved_base_path)
                        except ValueError:
                            rel_path = (
                                file_path.name if base_path.is_file() else file_path
                            )
                        rel_path_str = _sanitize_terminal_output(str(rel_path))

                    start_idx = match.start()
                    line_num = count_newlines("\n", 0, start_idx) + 1

                    snippet_start = rfind_newline("\n", 0, start_idx) + 1
                    snippet_end = find_newline("\n", start_idx)
                    if snippet_end == -1:
                        snippet_end = len(content)
                    snippet = content[snippet_start:snippet_end].strip()[:120]

                    findings.append(
                        build_finding(
                            "appguardrail-rule",
                            rule_id,
                            severity,
                            message,
                            rel_path_str,
                            line_num,
                            snippet,
                        )
                    )
    except (OSError, PermissionError):
        pass

    return findings


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "INFO": 3}
_SEVERITY_ICONS = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "WARNING": "🟡 WARNING",
    "INFO": "🔵 INFO",
}


def _print_scan_results(findings, files_scanned):
    """Print sorted findings and deploy-gate summary counts."""
    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 99))

    counts = {"CRITICAL": 0, "HIGH": 0, "WARNING": 0, "INFO": 0}
    non_blocking = 0
    for f in findings:
        if f.get("context", "app-code") not in NON_BLOCKING_CONTEXTS:
            counts[f["severity"]] += 1
        elif f.get("context", "app-code") in NON_BLOCKING_CONTEXTS:
            non_blocking += 1
        icon = _SEVERITY_ICONS.get(f["severity"], f["severity"])
        print(f"[{icon}] {f['file']}:{f['line']}")
        print(f"  Rule:    {f['rule_id']}")
        print(
            f"  Details: {f.get('source', 'appguardrail-rule')} | {f.get('category', 'misconfig')} | {f.get('context', 'app-code')}"
        )
        print(f"  Message: {f['message']}")
        print(f"  Code:    {f['snippet']}")
        if f.get("context", "app-code") in NON_BLOCKING_CONTEXTS:
            print("  Gate:    non-blocking context")
        print()

    print("─" * 60)
    files_word = "file" if files_scanned == 1 else "files"
    critical_word = "critical issue" if counts["CRITICAL"] == 1 else "critical issues"
    high_word = "high issue" if counts["HIGH"] == 1 else "high issues"
    warnings_word = "warning" if counts["WARNING"] == 1 else "warnings"
    info_word = "info issue" if counts["INFO"] == 1 else "info issues"

    print(
        f"Scanned {files_scanned} {files_word}  |  Deploy blockers: "
        f"🔴 {counts['CRITICAL']} {critical_word}  "
        f"🟠 {counts['HIGH']} {high_word}  "
        f"🟡 {counts['WARNING']} {warnings_word}  "
        f"🔵 {counts['INFO']} {info_word}"
    )
    if non_blocking:
        finding_word = "finding" if non_blocking == 1 else "findings"
        print(
            f"Non-blocking {finding_word} in docs/tests/examples/fixtures: {non_blocking}"
        )

    if files_scanned == 0:
        print("\n⚠️  No files were scanned. Are you in the right directory?")
    elif counts["CRITICAL"] > 0:
        issue_word = "issue" if counts["CRITICAL"] == 1 else "issues"
        print(f"\n❌ Critical {issue_word} found. Fix before deploying.")
    elif counts["HIGH"] > 0:
        issue_word = "issue" if counts["HIGH"] == 1 else "issues"
        print(f"\n⚠️  High-severity {issue_word} found. Review before deploying.")
    elif not findings:
        print("\n✅ No issues found in this scan.")
    else:
        print("\n✅ No deploy-blocking critical or high issues found.")

    if findings:
        these_word = "this issue" if len(findings) == 1 else "these issues"
        print(
            f"\n💡 Run 'appguardrail review' to get an AI prompt for fixing {these_word}."
        )
    print()


def cmd_review(args):
    """Generate a security review prompt for the given stack."""
    stack = getattr(args, "stack", None)
    db = getattr(args, "db", None)
    payments = getattr(args, "payments", None)

    prompt = REVIEW_PROMPT_BASE

    if stack and "nextjs" in stack:
        prompt += REVIEW_PROMPT_NEXTJS
    if db == "supabase" or (stack and "supabase" in stack):
        prompt += REVIEW_PROMPT_SUPABASE
    if db == "firebase" or (stack and "firebase" in stack):
        prompt += REVIEW_PROMPT_FIREBASE
    if payments == "stripe":
        prompt += REVIEW_PROMPT_STRIPE

    prompt += REVIEW_PROMPT_FOOTER

    print("\n" + "═" * 60)
    print("  AppGuardrail — Copy this prompt into your AI coding assistant")
    print("═" * 60 + "\n")
    print(prompt)
    print("═" * 60 + "\n")
    print("💡 Tips:")
    print("  - Paste this into Claude Code, Cursor, or any AI assistant")
    print("  - Include relevant files as context (API routes, DB schema, etc.)")
    print("  - Run 'appguardrail scan .' first to identify specific files to review")
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    """Parse CLI arguments and dispatch the requested AppGuardrail command."""
    parser = argparse.ArgumentParser(
        prog="appguardrail",
        description="Security guardrails for AI-built apps",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command")

    # init
    init_parser = subparsers.add_parser(
        "init", help="Install security rules into your project"
    )
    init_parser.add_argument(
        "--tool",
        choices=[
            "auto",
            "codex",
            "copilot",
            "cursor",
            "claude-code",
            "windsurf",
            "lovable",
        ],
        default="auto",
        help="AI coding tool or agent suite (default: auto)",
    )
    init_parser.add_argument(
        "--stack",
        help="Tech stack (e.g. nextjs-supabase, nextjs-firebase)",
    )

    # scan
    scan_parser = subparsers.add_parser(
        "scan", help="Scan a directory for security issues"
    )
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Directory or file to scan (default: current directory)",
    )
    scan_parser.add_argument(
        "--trivy",
        action="store_true",
        help="Also run Trivy filesystem scan for dependency, secret, and misconfiguration findings",
    )
    scan_parser.add_argument(
        "--external",
        choices=["auto", "off"],
        default="auto",
        help="Auto-discover runnable SAST/DAST engines for detected languages (default: auto)",
    )
    scan_parser.add_argument(
        "--bandit",
        action="store_true",
        help="Force-run Bandit Python SAST",
    )
    scan_parser.add_argument(
        "--ruff",
        action="store_true",
        help="Force-run Ruff Bandit-compatible security rules",
    )
    scan_parser.add_argument(
        "--semgrep",
        action="store_true",
        help="Force-run Semgrep multi-language SAST",
    )
    scan_parser.add_argument(
        "--semgrep-config",
        default=None,
        help="Semgrep config to use when Semgrep runs (default: auto)",
    )
    scan_parser.add_argument(
        "--zap-baseline",
        default=None,
        help="Run OWASP ZAP baseline scan against this http(s) URL",
    )
    scan_parser.add_argument(
        "--codegraph",
        action="store_true",
        help="Initialize or sync CodeGraph before scanning for structural review context",
    )

    # monitor
    subparsers.add_parser(
        "monitor",
        help="Install a GitHub Actions workflow that runs AppGuardrail on changes",
    )

    # review
    review_parser = subparsers.add_parser(
        "review", help="Generate an AI security review prompt"
    )
    review_parser.add_argument("--stack", help="Tech stack (e.g. nextjs)")
    review_parser.add_argument(
        "--db", help="Database/backend (e.g. supabase, firebase)"
    )
    review_parser.add_argument("--payments", help="Payment provider (e.g. stripe)")

    # hook
    hook_parser = subparsers.add_parser(
        "hook", help="Install a pre-commit hook to block commits with vulnerabilities"
    )
    hook_parser.add_argument(
        "--codegraph",
        action="store_true",
        help="Install the hook in CodeGraph mode so commits also refresh structural context",
    )

    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args)
    elif args.command == "scan":
        sys.exit(cmd_scan(args))
    elif args.command == "monitor":
        sys.exit(cmd_monitor(args))
    elif args.command == "review":
        cmd_review(args)
    elif args.command == "hook":
        sys.exit(cmd_hook(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
