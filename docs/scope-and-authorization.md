# Scope and Authorization

## Security Testing Requires Explicit Authorization

**Before scanning, testing, or reviewing any application using VibeSec, you must have explicit written authorization from the application owner.**

Unauthorized security testing — even with good intentions — may violate:

- Computer fraud and abuse laws (e.g., CFAA in the United States)
- Cybercrime laws in other jurisdictions
- Terms of service of cloud providers (Supabase, Firebase, Vercel, AWS, etc.)
- GDPR and other data protection regulations

---

## What Counts as Authorization

Authorization must be:

- **Explicit** — "You may test this application" is sufficient. Silence or implied permission is not.
- **From the owner** — The person authorizing testing must have the right to authorize it (e.g., the company owner, CTO, or delegated security lead).
- **In scope** — The authorization should specify what is in scope (e.g., specific URLs, repositories, environments).

A simple written statement (email is fine) like this is sufficient for most engagements:

> "I [Name], [Title] at [Company], authorize [Reviewer Name] to perform a security review of the application at [URL/Repo]. The review may include code analysis and non-destructive testing of the production/staging environment between [dates]."

---

## Defining Scope for VibeSec Engagements

Before starting a review, document:

### In Scope
- [ ] Repository URL(s) and branch(es)
- [ ] Application URL(s) (staging / production)
- [ ] Specific features or components to review
- [ ] Credentials provided for testing (test accounts)
- [ ] Time window for testing

### Out of Scope
- [ ] Third-party services (Supabase infrastructure, Vercel infrastructure, Stripe)
- [ ] Other tenants or users' data (do not attempt to access real user data)
- [ ] DoS/DDoS testing
- [ ] Social engineering
- [ ] Physical security

---

## Rules of Engagement

### Do
- Use only test accounts and test data provided or created for testing purposes.
- Report all findings to the application owner promptly.
- Stop and notify the owner immediately if you find evidence of a live breach.
- Keep findings confidential until remediation is complete.

### Do Not
- Access, download, or exfiltrate real user data, even as proof of concept.
- Use automated scanners that generate excessive load on production systems.
- Exploit found vulnerabilities beyond what is necessary to demonstrate impact.
- Disclose findings publicly without the owner's written consent.

---

## Responsible Disclosure

If you are using VibeSec tools to assess an application you do **not** own and did **not** have explicit authorization to test:

1. **Stop immediately.**
2. **Do not store or share any data accessed.**
3. If you found a genuine vulnerability in someone else's app, consider responsible disclosure via the app's security contact (`security@domain.com`) or a coordinated disclosure process.

---

## For VibeSec Contributors

If you are contributing scanner rules or detection patterns to this repository:

- Rules should detect dangerous patterns **in code**, not actively exploit vulnerabilities.
- Do not include actual exploit code or working proof-of-concept attack scripts.
- Rules should minimize false positives to avoid alarming developers unnecessarily.
- Test rules against the example apps in `examples/` before submitting.
