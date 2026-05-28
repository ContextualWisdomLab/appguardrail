# VibeSec Methodology

## Overview

VibeSec is designed to find and fix security issues that appear specifically in applications built with AI coding assistants (Cursor, Claude Code, Windsurf, Lovable, Replit, Bolt, etc.).

Traditional security scanners are optimized for classic web vulnerabilities — SQL injection, cross-site scripting, buffer overflows. These are important, but vibe-coded apps have a different failure profile:

| Traditional scanners target | Vibe-coded apps fail at |
|---|---|
| SQL injection | Missing ownership checks (IDOR) |
| XSS | Exposed service role keys |
| Buffer overflow | Supabase/Firebase misconfiguration |
| Unpatched CVEs | Hardcoded secrets |
| | Webhook signature bypass |
| | Admin routes with no role check |
| | AI-generated "TODO: add auth later" |

---

## Why AI-Generated Code Has a Unique Security Profile

AI coding tools are optimized to generate working, functional code quickly. Security is often deferred:

- **Authentication** is usually generated (login/signup flows exist), but **authorization** (ownership checks on individual resources) is frequently missing.
- **Secrets** are often hardcoded in early iterations and forgotten.
- **Supabase/Firebase** configuration is auto-generated with permissive defaults.
- **Webhook handlers** are scaffolded without signature verification.
- **Comments** like `// TODO: add auth` or `// skip for now` are common — and frequently deployed to production unchanged.

---

## The VibeSec Review Layers

### Layer 1: Automated Scan (VibeSec Scan)

A lightweight static analysis pass that detects:

- Hardcoded secrets (API keys, JWTs, database URLs)
- Dangerous environment variable patterns (NEXT_PUBLIC_ on secrets)
- Firebase rules set to `allow read, write: if true`
- Supabase `getSession()` used server-side instead of `getUser()`
- TODO/FIXME comments that bypass security
- CORS set to `*` on authenticated endpoints
- Empty Stripe webhook secrets

**What it does not replace:** Manual review, logic errors, complex IDOR chains.

### Layer 2: Manual Code Review (VibeSec Review)

A human-in-the-loop review of:

- Every API route — is authentication present? Is ownership verified?
- Database access patterns — are queries scoped to the authenticated user?
- Supabase RLS policies — are they correct and comprehensive?
- Firebase security rules — are they enforcing authentication and ownership?
- Payment flows — are prices server-side? Is webhook auth in place?
- Admin routes — are role checks present and correct?
- Environment variable usage — are secrets server-side only?

### Layer 3: Business Logic Review

VibeSec also considers application-level logic:

- Can a user escalate their own subscription tier?
- Can a user access premium features without paying?
- Can the payment amount be manipulated?
- Are there race conditions in critical operations?
- Can an attacker enumerate other users' IDs?

---

## The VibeSec Fix Format

Every finding is delivered in a format designed for AI-assisted remediation:

```
Problem: [plain-language description]
Risk: [impact if exploited]
Fix Prompt: [paste into Claude Code / Cursor]
Verification: [step-by-step test to confirm fix]
```

This is different from a traditional security report because:

1. The developer can paste the fix prompt directly into their AI coding tool.
2. The verification step is concrete and testable, not vague.
3. The risk description is in business terms, not CVE jargon.

---

## Severity Levels

| Level | Definition | Example |
|---|---|---|
| 🔴 Critical | Immediate data exposure or financial impact | IDOR on all user records, Stripe price manipulation |
| 🟠 High | Significant risk, exploitable with low effort | Missing auth on API route, hardcoded secret |
| 🟡 Medium | Risk requires specific conditions | CORS misconfiguration, missing rate limit |
| 🔵 Info | Best practice improvement | Missing security header, outdated dependency |

---

## Limitations

VibeSec review is **not** equivalent to:

- A full penetration test
- A red team engagement
- Infrastructure security review
- Compliance certification (SOC 2, ISO 27001, PCI-DSS)

VibeSec focuses specifically on application-layer security for AI-generated web apps. For comprehensive security programs, engage a qualified security firm.

---

## Continuous Security (VibeSec Monitor)

Vibe-coded apps change frequently — AI tools add features rapidly. Every commit is a potential security regression.

VibeSec Monitor tracks:

| Trigger | What VibeSec checks |
|---|---|
| New commit | Security-relevant diff analysis |
| New API route | Auth + ownership check presence |
| Env change | Secret exposure check |
| Supabase/Firebase rule change | Permissiveness regression |
| New dependency | Known CVEs + typosquatting check |
| Deploy | Public endpoints, headers, exposed files |
| Payment feature added | Webhook, price integrity, auth checks |
