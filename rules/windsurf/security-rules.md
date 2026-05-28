# VibeSec Security Rules for Windsurf

Add these rules to your Windsurf project. Place this file or its contents in your project's `.windsurf/rules/vibesec.md` (or equivalent Windsurf rules location).

---

## Core Security Principles

### 1. Authentication First

Every server-side function, API route, or server action must authenticate the caller before doing anything else.

```typescript
// Always the first thing in a protected handler
const session = await getServerSession(authOptions);
if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });
```

### 2. Authorization Always

After confirming who the user is, confirm they own what they are requesting.

```typescript
const record = await db.query.find({ where: { id: params.id } });
if (!record || record.userId !== session.user.id) {
  return Response.json({ error: "Forbidden" }, { status: 403 });
}
```

### 3. No Client-Side Secrets

- `SUPABASE_SERVICE_ROLE_KEY` → server-only
- `STRIPE_SECRET_KEY` → server-only
- `DATABASE_URL` → server-only
- `JWT_SECRET` → server-only

If you must reference a variable in a client component, it must use `NEXT_PUBLIC_` **and** must not be a privileged secret.

### 4. Validate All Inputs

Use Zod (or equivalent) to validate every incoming request body, query parameter, and URL segment.

```typescript
const schema = z.object({ projectId: z.string().uuid() });
const parsed = schema.safeParse(req.body);
if (!parsed.success) return Response.json({ error: "Invalid input" }, { status: 400 });
```

### 5. Stripe Webhooks — Always Verify

```typescript
const event = stripe.webhooks.constructEvent(
  await req.text(),
  req.headers.get("stripe-signature")!,
  process.env.STRIPE_WEBHOOK_SECRET!
);
```

### 6. Supabase RLS — Always On

- Enable RLS on every table.
- Write explicit `SELECT`, `INSERT`, `UPDATE`, `DELETE` policies.
- Use `auth.uid()` in policies to bind rows to their owner.

### 7. File Uploads — Server-Side Validation

```typescript
const ALLOWED_TYPES = ["image/jpeg", "image/png", "application/pdf"];
const MAX_SIZE = 10 * 1024 * 1024; // 10 MB
if (!ALLOWED_TYPES.includes(file.type) || file.size > MAX_SIZE) {
  return Response.json({ error: "Invalid file" }, { status: 400 });
}
```

### 8. Security Headers

Ensure every response includes:
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy` (restrict `default-src`)

---

## Red Flags — Ask Before Proceeding

If Windsurf is about to generate code that does any of the following, stop and reconsider:

- Skips authentication in a data-fetching handler
- Passes user input directly to a database call without validation
- Uses a service role key in a client component
- Sets CORS to `*` on an authenticated endpoint
- Processes a Stripe webhook without verifying the signature
- Reads or writes files using a user-supplied filename
