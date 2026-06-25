# AppGuardrail

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/ContextualWisdomLab/appguardrail)
[![Security Process](https://github.com/ContextualWisdomLab/appguardrail/actions/workflows/security-process.yml/badge.svg)](https://github.com/ContextualWisdomLab/appguardrail/actions/workflows/security-process.yml)

**Security guardrails for AI-built apps.**

AppGuardrail was formerly developed as VibeSec. The rename avoids the occupied third-party PyPI `vibesec` namespace.

AppGuardrail helps builders using Cursor, Claude Code, Lovable, Replit, Bolt, Supabase, Firebase, Vercel, and Netlify find and fix security issues introduced during AI-assisted development.

> **AI 생성 앱을 위한 보안 가드레일.**
> AppGuardrail은 Cursor, Claude Code, Lovable, Replit, Bolt, Supabase, Firebase, Vercel, Netlify로 만든 앱에서 자주 발생하는 보안 문제를 찾고 고칠 수 있게 돕습니다.

---

## What is AppGuardrail?

AppGuardrail is a **persistent security layer for AI-assisted builders** — not a one-time pentest, but a security co-pilot that stays with you through the entire lifecycle of your AI-built app: coding, deployment, operation, updates, and incident response.

> AppGuardrail = AI 앱 빌더의 미니 보안팀

---

## What AppGuardrail Provides

| Layer | Description |
|---|---|
| 🛡️ **AppGuardrail Rules** | Security rules for AI coding assistants (Cursor, Claude Code, Windsurf, Lovable) |
| 🔍 **AppGuardrail Scan** | Lightweight static analysis for secrets, auth gaps, misconfigurations |
| 👁️ **AppGuardrail Review** | Human-readable review templates and AI-powered audit prompts |
| 📡 **AppGuardrail Monitor** | Continuous security checks triggered by commits, deploys, and feature additions |
| 🔧 **AppGuardrail Fix** | AI-ready fix prompts + patch guidance + re-verification steps |

---

## Quick Start

### Run the CLI

Requires Python 3.9 or newer.

Install from PyPI:

```bash
python3 -m pip install appguardrail
appguardrail --help
```

### Initialize security rules in your project

```bash
# For Cursor users
appguardrail init --tool cursor

# For Claude Code users
appguardrail init --tool claude-code

# For a Next.js + Supabase stack
appguardrail init --stack nextjs-supabase
```

This creates:
- `.cursor/rules/appguardrail.md`
- `CLAUDE.md`
- `APPGUARDRAIL_CHECKLIST.md`

### Scan your codebase

```bash
appguardrail scan .

# Also run Trivy FS for dependency CVEs, secrets, and IaC misconfigurations
appguardrail scan --trivy .
```

Detects:
- Hardcoded secrets (`SUPABASE_SERVICE_ROLE_KEY`, `STRIPE_SECRET_KEY`, etc.)
- Trivy-backed dependency vulnerabilities, secrets, and misconfigurations
- Dangerous Supabase/Firebase usage patterns
- API routes missing authentication
- Public Firebase rules (`read/write: true`)
- Dangerous CORS settings (`origin: "*"`)
- Missing Stripe webhook signature verification
- Unprotected admin routes
- Risky file upload handlers

Deploy-blocking counts focus on app code. Findings in docs, tests, examples,
and scanner fixtures stay visible but do not fail the deploy gate by default.

### Generate a security review prompt

```bash
appguardrail review --stack nextjs --db supabase --payments stripe
```

Outputs a prompt you can paste directly into Claude Code or Cursor.

---

## Repository Structure

```
appguardrail/
├── README.md
├── rules/                        # Security rules for AI coding tools
│   ├── cursor/
│   ├── claude-code/
│   ├── windsurf/
│   └── lovable/
├── checklists/                   # Stack-specific security checklists
│   ├── auth.md
│   ├── authorization.md
│   ├── supabase.md
│   ├── firebase.md
│   ├── stripe.md
│   ├── file-upload.md
│   ├── api-security.md
│   ├── secrets.md
│   └── deployment.md
├── prompts/                      # AI fix and review prompts
│   ├── secure-code-review.md
│   ├── fix-authz-bugs.md
│   ├── supabase-rls-review.md
│   ├── stripe-webhook-review.md
│   └── admin-route-review.md
├── scanner/                      # Lightweight static analysis engine
│   ├── rules/
│   │   ├── secrets.yml
│   │   ├── authz.yml
│   │   ├── supabase.yml
│   │   ├── firebase.yml
│   │   ├── nextjs.yml
│   │   └── stripe.yml
│   └── cli/
│       └── appguardrail.py
├── reports/                      # Report templates
│   └── templates/
│       ├── founder-friendly-report.md
│       ├── agency-report.md
│       └── fix-pack.md
├── examples/                     # Sample vulnerable and fixed apps
│   ├── vulnerable-vibe-app/
│   └── fixed-vibe-app/
└── docs/                         # Methodology and responsible testing
    ├── methodology.md
    ├── scope-and-authorization.md
    └── responsible-testing.md
```

---

## The AppGuardrail Fix Format

AppGuardrail doesn't hand you a traditional security report. Every finding comes with:

```
Problem:
  User A can access User B's project data by supplying B's project_id.

Risk:
  Customer data may be exposed across users.

Fix Prompt:
  "Update all project API routes to verify that the authenticated user's id
   matches project.owner_id before returning data. Return 403 when ownership
   does not match. Add tests for cross-user access."

Verification:
  Request User B's project_id using User A's token → expect HTTP 403.
```

---

## Why AppGuardrail is Different from Traditional SAST

Traditional scanners target classic vulnerabilities (SQLi, XSS). AI-coded apps fail differently:

| AI-coding failure mode | Example |
|---|---|
| Missing ownership check | Any user can read any record |
| Public storage bucket | Files accessible without auth |
| Exposed service role key | Full DB access from the browser |
| Supabase/Firebase rule mistake | RLS disabled or `allow read: if true` |
| Insecure webhook | No Stripe signature verification |
| AI-generated temporary code | `// TODO: add auth later` left in production |

---

## Services (Paid)

| Product | Description |
|---|---|
| **AppGuardrail Snapshot** | One-time security assessment of your current app |
| **AppGuardrail Review** | Code, config, and authorization structure review |
| **AppGuardrail Red Team Lite** | Defensive penetration test based on real user scenarios |
| **AppGuardrail Fix Pack** | Patches and prompts to fix discovered issues |
| **AppGuardrail Retainer** | Monthly security review of every change |
| **AppGuardrail Monitor** | Continuous automated monitoring on every commit/deploy |

---

## Contributing

This project is open-source and welcomes contributions of:
- New security rules for AI coding tools
- Stack-specific checklists
- Fix prompts for common vulnerability patterns
- Scanner detection rules

Please read [docs/responsible-testing.md](docs/responsible-testing.md) before contributing scanner rules.

---

## License

MIT — see [LICENSE](LICENSE)
