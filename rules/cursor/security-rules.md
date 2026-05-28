# VibeSec Security Rules for Cursor

Add these rules to your Cursor project by placing this file at `.cursor/rules/vibesec.md`.

---

## Authentication & Authorization

- Every API route must verify that the request is authenticated before accessing any data.
- Never rely on frontend-only authorization. Always enforce access control server-side.
- For every user-owned resource, verify `owner_id` (or equivalent) matches the current session user before returning or modifying data.
- Return `403 Forbidden` (not `404`) when a user attempts to access a resource they do not own.
- Never expose admin or internal APIs without role-based access checks.

## Secrets & Environment Variables

- Never hardcode secrets, API keys, or credentials directly in source code.
- Never use `SUPABASE_SERVICE_ROLE_KEY` or any service role / admin key on the client side.
- All secret environment variables must be server-side only and never sent to the browser.
- Do not commit `.env` files. Ensure `.env`, `.env.local`, `.env.production` are listed in `.gitignore`.
- Never log sensitive values (tokens, passwords, keys) to the console.

## API Route Security

- When generating API routes, always enforce authentication and ownership checks.
- Every mutating endpoint (POST, PUT, PATCH, DELETE) must validate the authenticated user's ownership of the affected resource.
- Add server-side input validation to all API route parameters, query strings, and request bodies.
- Never trust client-supplied IDs to determine access; always re-validate against the session user.

## Database & ORM

- Use parameterized queries or ORM-level abstractions. Never concatenate user input into SQL strings.
- Row-level security (RLS) must be enabled for all Supabase tables that store user data.
- Never disable RLS for convenience; write proper policies instead.
- When using Supabase `service_role` for admin operations, isolate that logic in server-only files.

## File Uploads

- Validate file extension, MIME type, and file size on the server side for every upload.
- Do not use user-supplied filenames directly; generate a unique, sanitized filename server-side.
- Store uploaded files in private buckets by default; only expose public URLs when explicitly required.
- Scan uploaded files for malware if they can be served back to other users.

## Stripe & Payments

- Always verify the Stripe webhook signature (`stripe.webhooks.constructEvent`) before processing webhook events.
- Never trust client-supplied price or amount data; always look up prices server-side from Stripe.
- Protect billing management routes behind authentication and ownership checks.

## CORS & Security Headers

- Do not set `Access-Control-Allow-Origin: *` on endpoints that handle authenticated requests.
- Restrict CORS origins to known, trusted domains.
- Set security headers: `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.

## Testing

- Add tests for cross-user access denial on every resource endpoint.
- Add tests that confirm unauthenticated requests return `401`.
- Add tests that confirm requests with valid auth but wrong ownership return `403`.

---

## Example Patterns to Always Enforce

```typescript
// ✅ Correct: server-side ownership check
const project = await db.project.findUnique({ where: { id: projectId } });
if (!project || project.ownerId !== session.user.id) {
  return res.status(403).json({ error: "Forbidden" });
}

// ❌ Wrong: trusting client input without verification
const project = await db.project.findUnique({ where: { id: req.body.projectId } });
return res.json(project); // no ownership check!
```

```typescript
// ✅ Correct: secrets are server-side only
const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY! // server-side only
);

// ❌ Wrong: service role key exposed to the browser
const supabaseAdmin = createClient(url, process.env.NEXT_PUBLIC_SERVICE_ROLE_KEY!);
```
