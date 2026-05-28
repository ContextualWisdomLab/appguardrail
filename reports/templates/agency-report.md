# VibeSec Agency Security Review Report

**Client:** [Client Name]
**Project:** [Project / App Name]
**Reviewed by:** [Agency Name] powered by VibeSec
**Date:** [Date]
**Engagement type:** Pre-launch review / Ongoing retainer / Incident review

---

## Executive Summary

This report documents the security review of [App Name], a [brief description, e.g., "Next.js + Supabase SaaS application for managing team projects"].

**Critical findings requiring immediate action:** [N]
**High-severity findings:** [N]
**Total findings:** [N]

**Recommendation:** [Approved for launch with conditions / Hold pending critical fixes / Cleared]

---

## Methodology

This review used the VibeSec methodology for AI-generated web applications, focusing on:

1. **Static analysis** — Automated scanning for hardcoded secrets, dangerous patterns, and common misconfigurations
2. **Manual code review** — Review of authentication flows, authorization logic, and data access patterns
3. **Configuration review** — Supabase RLS policies, Firebase rules, CORS, security headers, and environment variable handling
4. **Business logic review** — Payment flows, file upload handling, and admin access controls

---

## Findings

### Critical Findings

#### C-01: [Title]

| Field | Value |
|---|---|
| **Severity** | Critical |
| **CVSS Score** | [e.g., 9.1] |
| **Category** | [e.g., Broken Access Control / Secrets Exposure / Injection] |
| **Affected Component** | [e.g., `/api/projects/[id]`] |
| **CWE** | [e.g., CWE-639: Authorization Bypass Through User-Controlled Key] |

**Description:**
[Technical description of the vulnerability.]

**Impact:**
[What an attacker can do. Be specific about data exposure, financial impact, etc.]

**Proof of Concept:**
```
[HTTP request or code snippet demonstrating the vulnerability]
```

**Remediation:**
```typescript
// [Code fix or fix prompt]
```

**References:**
- [OWASP Top 10 link or relevant standard]

---

### High Findings

#### H-01: [Title]

[Same format as above]

---

### Medium Findings

#### M-01: [Title]

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Category** | [Category] |
| **Affected Component** | [Component] |

**Description:** [Description]

**Remediation:** [Fix]

---

### Informational

#### I-01: [Title]

**Description:** [Description]

**Recommendation:** [Recommendation]

---

## Remediation Priority Matrix

| ID | Title | Severity | Effort | Priority |
|---|---|---|---|---|
| C-01 | [Title] | Critical | Low | Immediate |
| H-01 | [Title] | High | Medium | Before launch |
| M-01 | [Title] | Medium | Low | Within 30 days |

---

## Positive Findings

The following security controls were found to be correctly implemented:

- ✅ [e.g., Authentication middleware applied to all protected routes]
- ✅ [e.g., Stripe webhook signature verification implemented]
- ✅ [e.g., Input validation using Zod on all API routes]

---

## Retest Notes

[To be completed after remediation. Each finding should be retested and marked as Fixed / Partially Fixed / Not Fixed.]

| ID | Status | Notes |
|---|---|---|
| C-01 | ⏳ Pending | |
| H-01 | ⏳ Pending | |

---

## Appendix A: Tools Used

- vibesec scan
- Manual code review
- [Any other tools]

## Appendix B: Scope

**In scope:**
- [Repository / URL]
- [Specific functionality]

**Out of scope:**
- Third-party services (Supabase, Vercel, Stripe infrastructure)
- Social engineering
- Physical security

## Appendix C: References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [VibeSec Rules and Checklists](https://github.com/Seongho-Bae/VibeSec)
