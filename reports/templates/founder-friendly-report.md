# AppGuardrail Security Review Report

**App:** [App Name]
**Reviewed by:** AppGuardrail
**Date:** [Date]
**Version / Commit:** [Git SHA or version]

---

## Summary

| | Count |
|---|---|
| 🔴 Critical Issues | 0 |
| 🟠 High Issues | 0 |
| 🟡 Medium Issues | 0 |
| 🔵 Informational | 0 |

**Overall Status:** ⚠️ Not ready for public launch / ✅ Cleared for launch (delete one)

---

## What We Checked

- [ ] Authentication (login, session handling, protected routes)
- [ ] Authorization (ownership checks, IDOR prevention)
- [ ] Secrets & environment variables
- [ ] Database security (RLS, query injection)
- [ ] File uploads
- [ ] Payment integration (Stripe)
- [ ] API security (CORS, headers, rate limiting)
- [ ] Deployment configuration

---

## Findings

### Finding 1: [Short Title]

**Severity:** 🔴 Critical / 🟠 High / 🟡 Medium / 🔵 Info

**What we found:**
[Plain-language description of the issue. No jargon. Explain what the problem is and where it lives.]

**Why it matters:**
[What could happen if this is exploited? Who is affected? What data is at risk?]

**Example scenario:**
[A concrete example: "User A can visit /api/projects/[any-id] and read User B's private project data."]

**Fix prompt (paste into your AI coding assistant):**
```
[Exact prompt that the developer can copy into Claude Code, Cursor, etc. to fix this issue.]
```

**How to verify the fix:**
[Step-by-step instructions to confirm the fix works, e.g., "Log in as User A. Try to access User B's resource URL. You should see a 403 response."]

---

### Finding 2: [Short Title]

**Severity:** 🟠 High

**What we found:**
[Description]

**Why it matters:**
[Impact]

**Fix prompt:**
```
[Fix prompt]
```

**How to verify:**
[Verification steps]

---

## What's Good

[List things that are already done well. This builds trust and shows you actually reviewed the app, not just ran a scanner.]

- ✅ [e.g., Supabase RLS is enabled on the main user data tables]
- ✅ [e.g., Stripe webhook signature verification is in place]
- ✅ [e.g., Password hashing is handled by Supabase Auth]

---

## Recommended Next Steps

Prioritized by risk:

1. **[Most critical fix]** — Fix before any public access
2. **[Second priority]** — Fix before accepting payment data
3. **[Third priority]** — Fix within 30 days
4. **[Low priority]** — Good to have but not blocking

---

## Scope & Limitations

This review covered:
- Codebase: [repo URL or description]
- Period: [dates]
- Focus areas: [what was in scope]

This review did **not** cover:
- Infrastructure-level security (server configuration, network security)
- Third-party service security (Supabase, Vercel, Stripe internals)
- Business logic edge cases not described in the brief

---

## About AppGuardrail

AppGuardrail provides security reviews for apps built with AI coding tools. We specialize in the security issues that appear most often in Cursor, Claude Code, Lovable, Replit, and similar AI-assisted development workflows.

[https://github.com/ContextualWisdomLab/appguardrail](https://github.com/ContextualWisdomLab/appguardrail)
