#!/usr/bin/env python3
"""
appguardrail - Security guardrails for AI-built apps

Usage:
  appguardrail init [--tool <tool>] [--stack <stack>]
  appguardrail scan [--trivy] [--codegraph] [<path>]
  appguardrail review [--stack <stack>] [--db <db>] [--payments <payments>]
  appguardrail hook [--codegraph]
  appguardrail --help
  appguardrail --version

Commands:
  init      Install security rules into your project
  scan      Run a lightweight security scan on a directory
  review    Generate an AI review prompt for your stack
  hook      Install a pre-commit hook to block vulnerabilities

Options:
  --tool    AI coding tool: auto, codex, copilot, cursor, claude-code, windsurf, lovable (default: auto)
  --stack   Tech stack: nextjs, nextjs-supabase, nextjs-firebase, remix, sveltekit
  --db      Database/backend: supabase, firebase, prisma, drizzle
  --payments  Payment provider: stripe
  --trivy  Also run Trivy filesystem scan
  --codegraph  Initialize or sync a CodeGraph index before scanning
  --help    Show this help message
  --version Show version
"""

import argparse
import json
import os
import re
import shutil
import shlex
import stat
import subprocess
import sys
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

# ---------------------------------------------------------------------------
# Scan patterns
# ---------------------------------------------------------------------------

SCAN_RULES = [
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
        "id": "hardcoded-password",
        "pattern": re.compile(
            r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\x27][^"\x27\s]{6,}["\x27]'
        ),
        "severity": "HIGH",
        "message": "Possible hardcoded password detected. [OWASP A07:2021 - Identification and Authentication Failures]",
        "extensions": None,
    },
]

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
            "shared_only": True,
        },
    }
    tool_groups = {
        "auto": ["codex", "copilot", "claude-code", "cursor", "windsurf"],
    }

    selected_tools = tool_groups.get(tool, [tool])

    unknown_tools = [selected for selected in selected_tools if selected not in tool_configs]
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
                print(
                    f"{config['path']} already contains {config['append_marker']} rules — skipping."
                )
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

    if stack and "supabase" in stack:
        _print_supabase_reminder()

    print("\n✅ AppGuardrail initialized successfully!\n")
    print("Created/updated files:")
    for f in installed:
        print(f"  {f}")
    print()
    print("Next steps:")
    print("  1. Review the installed rules and customize for your project")
    print("  2. Run 'appguardrail scan .' to check for existing issues")
    print("  3. Check APPGUARDRAIL_CHECKLIST.md before deploying")
    print()


def _print_supabase_reminder():
    print("\n💡 Supabase stack detected. Quick reminders:")
    print("  - Enable RLS on every user-data table")
    print("  - Use getUser() not getSession() on the server")
    print("  - Keep SUPABASE_SERVICE_ROLE_KEY server-side only")
    print()


def cmd_scan(args):
    """Run a lightweight security scan."""
    scan_arg = Path(getattr(args, "path", ".") or ".")
    scan_path = scan_arg.resolve()
    run_trivy = getattr(args, "trivy", False)
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
        files_to_scan = _collect_files(scan_path)

    for file_path in files_to_scan:
        files_scanned += 1
        file_findings = _scan_file(file_path, scan_path)
        findings.extend(file_findings)

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

    _print_scan_results(findings, files_scanned)
    if files_scanned == 0:
        return 1
    return 1 if any(_is_deploy_blocking(f) for f in findings) else 0


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
            )
            for rule in SCAN_RULES
            if not rule["extensions"] or ext in rule["extensions"]
        ]
    return _RULES_CACHE[ext]


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
                            if (
                                entry.name not in SKIP_DIRS
                                and (
                                    not entry.name.startswith(".")
                                    or entry.name in SECURITY_HIDDEN_DIRS
                                )
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
    "stripe",
    "openai",
    "supabase-service-role",
)
_REDACTED_SENSITIVE_SNIPPET = "[REDACTED: sensitive match suppressed]"


def _is_sensitive_rule(rule_id: str) -> bool:
    lowered = (rule_id or "").lower()
    return any(token in lowered for token in _SENSITIVE_RULE_TOKENS)


def _safe_snippet(rule_id: str, snippet: str, category: str) -> str:
    if category == "secrets" or _is_sensitive_rule(rule_id):
        return _REDACTED_SENSITIVE_SNIPPET
    return _sanitize_terminal_output(snippet)


def _finding_context(file_path: str, snippet: str = "") -> str:
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
    rule = (rule_id or "").lower()
    if "cve-" in rule or "vulnerability" in rule:
        return "dependency"
    if any(
        token in rule
        for token in ("secret", "jwt", "password", "database-url", "openai")
    ):
        return "secrets"
    if "stripe" in rule or "webhook" in rule:
        return "payment"
    if "firebase" in rule or "supabase" in rule or "storage" in rule:
        return "storage"
    if any(token in rule for token in ("auth", "session", "admin")):
        return "authz"
    if any(token in rule for token in ("eval", "sql", "command", "path-traversal")):
        return "injection"
    return "misconfig"


def _confidence(rule_id: str) -> str:
    return "medium" if "todo" in (rule_id or "").lower() else "high"


def _build_finding(
    source, rule_id, severity, message, file, line, snippet, category=None
):
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
    return _TRIVY_SEVERITY_MAP.get((severity or "UNKNOWN").upper(), "INFO")


def _trivy_line(item: dict) -> int:
    metadata = item.get("CauseMetadata") or {}
    return item.get("StartLine") or metadata.get("StartLine") or 1


def _trivy_target(target: str, base_path: Path) -> str:
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
    trivy = shutil.which("trivy")
    if not trivy:
        raise RuntimeError(
            "trivy executable not found. Install Trivy or run without --trivy."
        )

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
        capture_output=True,
        text=True,
        check=False,
    )
    if process.returncode != 0:
        detail = (process.stderr or process.stdout).strip().splitlines()
        raise RuntimeError("Trivy scan failed" + (f": {detail[-1]}" if detail else "."))

    try:
        report = json.loads(process.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Trivy returned invalid JSON: {exc}") from exc

    return _trivy_findings(report, scan_path)


def _run_codegraph_command(command, cwd: Path, action: str):
    if not command:
        raise RuntimeError("CodeGraph command cannot be empty.")
    for arg in command:
        if not isinstance(arg, str):
            raise RuntimeError(
                f"CodeGraph command argument must be a string, got {type(arg).__name__}."
            )
        if not arg.isprintable():
            raise RuntimeError("CodeGraph command argument contains control characters.")

    executable = Path(command[0]).name
    allowed_args = {("sync",), ("init", "-i"), ("status",)}
    if executable != "codegraph" or tuple(command[1:]) not in allowed_args:
        raise RuntimeError(f"Unsupported CodeGraph {action} command.")

    process = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if process.returncode != 0:
        detail = (process.stderr or process.stdout).strip().splitlines()
        suffix = f": {detail[-1]}" if detail else "."
        raise RuntimeError(f"CodeGraph {action} failed{suffix}")
    return (process.stdout or "").strip()


def _run_codegraph_index(scan_path: Path):
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
        raise RuntimeError(f"CodeGraph path exists but is not a directory: {codegraph_dir}")
    if codegraph_dir.is_dir():
        _run_codegraph_command([codegraph, "sync"], workdir, "sync")
    else:
        _run_codegraph_command([codegraph, "init", "-i"], workdir, "init")

    return _run_codegraph_command([codegraph, "status"], workdir, "status")


def _scan_file(file_path: Path, base_path: Path):
    """Scan a single file and return a list of findings."""
    findings = []

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
    build_finding = _build_finding

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            if not content:
                return findings
            count_newlines = content.count
            find_newline = content.find
            rfind_newline = content.rfind

            for rule_id, severity, message, finditer in applicable_rules:
                for match in finditer(content):
                    if rel_path_str is None:
                        try:
                            rel_path = file_path.relative_to(
                                base_path if base_path.is_dir() else Path(".").resolve()
                            )
                        except ValueError:
                            rel_path = file_path.name if base_path.is_file() else file_path
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
        print(f"Non-blocking findings in docs/tests/examples/fixtures: {non_blocking}")

    if files_scanned == 0:
        print("\n⚠️  No files were scanned. Are you in the right directory?")
    elif counts["CRITICAL"] > 0:
        print("\n❌ Critical issues found. Fix before deploying.")
    elif counts["HIGH"] > 0:
        print("\n⚠️  High-severity issues found. Review before deploying.")
    elif not findings:
        print("\n✅ No issues found in this scan.")
    else:
        print("\n✅ No deploy-blocking critical or high issues found.")

    if findings:
        print("\n💡 Run 'appguardrail review' to get an AI prompt for fixing these issues.")
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
        "--codegraph",
        action="store_true",
        help="Initialize or sync CodeGraph before scanning for structural review context",
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
    elif args.command == "review":
        cmd_review(args)
    elif args.command == "hook":
        sys.exit(cmd_hook(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
