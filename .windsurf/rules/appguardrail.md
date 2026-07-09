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
