# Responsible Testing Guidelines

## Principles

VibeSec is a security tool. Like all security tools, it can be used responsibly or irresponsibly. These guidelines exist to ensure VibeSec is used to protect applications and their users — not to harm them.

---

## The Prime Directive

**Only test applications you own or have explicit written authorization to test.**

See [scope-and-authorization.md](scope-and-authorization.md) for details on what authorization means and how to document it.

---

## For Developers (Testing Your Own Apps)

### Safe Practices

**Use a dedicated test environment:**
- Test against a staging environment, not production.
- Use test database instances with synthetic data — no real user data.
- Create dedicated test accounts (never test with a real customer's account).

**Limit blast radius:**
- Use test API keys for Stripe, OpenAI, etc. (not live keys).
- Ensure test actions cannot affect real users (use isolated namespaces/tenants).

**Keep findings private:**
- If you find a vulnerability in your own app, fix it before sharing publicly.
- Share findings only with team members who need to know.

**Document what you tested:**
- Keep a brief log: what you tested, when, what you found.
- This helps track which issues have been verified and fixed.

---

## For Agencies and Consultants

### Before the Engagement

1. **Get written authorization** from the client (see scope-and-authorization.md).
2. **Define scope** clearly — what is included and excluded.
3. **Agree on a communication plan** — who gets notified of critical findings and how quickly.
4. **Set up test accounts** — the client should provide dedicated test credentials.

### During the Engagement

1. **Use test accounts only.** Never log in with a real customer's credentials.
2. **Do not access or download real user data** as part of demonstrating a vulnerability.
   - To demonstrate an IDOR, access your own test user's data with another test user — not real data.
3. **Avoid destructive testing** unless explicitly authorized:
   - No deleting production data
   - No sending emails to real users
   - No triggering real payment charges
4. **Stop and escalate** if you find evidence of:
   - An existing breach or compromise
   - Data that suggests real user PII has been exposed
   - Credentials that appear to belong to third parties

### After the Engagement

1. **Delete any test data** you created in client systems.
2. **Deliver findings securely** — encrypted email, shared secure folder, or a private report link.
3. **Allow time for remediation** before any public disclosure.
4. **Do not retain copies** of client code, credentials, or findings beyond the agreed retention period.

---

## For Open-Source Contributors

### Scanner Rules

- Rules must detect code patterns that are dangerous — they must not contain working exploit code.
- Test rules against the `examples/vulnerable-vibe-app/` sample before submitting.
- Document why the pattern is dangerous and what the correct pattern looks like.
- Minimize false positives: a rule that fires on safe code causes alert fatigue.

### Example Applications

- `examples/vulnerable-vibe-app/` is intentionally insecure for educational purposes.
- Never deploy the vulnerable example app to a public URL.
- The vulnerable app must use fake data only — no connection to real services.
- The vulnerable app must clearly display a warning that it is intentionally vulnerable.

### Checklists and Prompts

- Prompts and checklists should guide developers toward secure practices.
- Do not include prompts that could help an attacker exploit applications.
- Prompts should be defensive (fix this) not offensive (find this to exploit).

---

## Reporting Vulnerabilities in VibeSec Itself

If you find a security vulnerability in the VibeSec tools or scanner:

1. Do not disclose it publicly until a fix is available.
2. Report it via a GitHub Security Advisory (private) or email the maintainer.
3. Allow reasonable time for a fix before public disclosure.

---

## Legal Notice

VibeSec tools are provided for legitimate security testing and educational purposes only. The maintainers are not responsible for misuse. By using VibeSec, you agree to use it only on applications you own or have explicit written authorization to test.
