# AppGuardrail Security Instructions

Apply these rules when suggesting code, reviewing pull requests, or generating fixes:

- Protected routes must authenticate first and authorize user-owned resources server-side.
- Do not place service-role keys, admin keys, Stripe secrets, or webhook secrets in client code.
- Validate all request inputs and uploaded files before use.
- Verify Stripe webhook signatures with the raw body and signing secret.
- Prefer tests that prove cross-user access returns 403.
- Run or recommend `appguardrail scan --codegraph .` for security-sensitive changes when CodeGraph is installed.
- Treat AppGuardrail critical/high findings in app code as deploy blockers.
