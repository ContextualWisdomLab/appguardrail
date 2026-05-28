# VibeSec Secure Build Checklist for Lovable

Use this checklist when building or reviewing an app generated with Lovable. Paste the relevant sections as context into your Lovable prompt to enforce security from the start.

---

## Prompt Prefix (Add to Every Lovable Build Session)

```
Before generating any code, apply these security rules:

1. Every API route or server action must check authentication before accessing data.
2. Every resource endpoint must verify the authenticated user owns the requested record.
3. Never expose SUPABASE_SERVICE_ROLE_KEY or any admin key to the client.
4. Enable Supabase Row Level Security on every table that stores user data.
5. Validate all inputs (body, params, query) with Zod before processing.
6. Verify Stripe webhook signatures before processing payment events.
7. Never set CORS to allow all origins on authenticated endpoints.
8. Generate secure, server-side filenames for file uploads; validate type and size.
```

---

## Pre-Launch Security Checklist

### Authentication
- [ ] Login, signup, and session handling work correctly
- [ ] All protected pages redirect unauthenticated users to login
- [ ] Session tokens are stored securely (httpOnly cookies or Supabase session)
- [ ] Password reset flow validates token before allowing password change

### Authorization
- [ ] Every API route that returns user data checks `userId === session.user.id`
- [ ] Admin routes are protected by a role check (not just by being hidden in the UI)
- [ ] Users cannot access each other's data by changing IDs in the URL

### Supabase
- [ ] RLS is enabled on all tables (`ALTER TABLE ... ENABLE ROW LEVEL SECURITY`)
- [ ] SELECT policies use `auth.uid() = user_id` (or equivalent)
- [ ] INSERT policies prevent users from creating records owned by other users
- [ ] `service_role` key is never referenced in client-side code
- [ ] Storage buckets that hold user files are private (not public)

### Secrets
- [ ] `.env` is in `.gitignore`
- [ ] No hardcoded keys in source code
- [ ] `NEXT_PUBLIC_` variables contain no privileged secrets

### Payments (Stripe)
- [ ] Webhook handler calls `stripe.webhooks.constructEvent` and rejects on failure
- [ ] Prices are fetched from Stripe server-side, not from client-supplied values
- [ ] Billing portal / customer management is behind auth + ownership checks

### File Uploads
- [ ] File type validated server-side (MIME + extension)
- [ ] File size limited server-side
- [ ] Filenames are generated server-side (UUID or hash)

### Deployment
- [ ] Environment variables are set in Vercel/Netlify dashboard, not committed to the repo
- [ ] HTTPS is enforced
- [ ] Security headers are configured (`next.config.js` headers or middleware)
- [ ] Error messages do not expose stack traces or internal details to users

---

## Common Lovable / Supabase Mistakes to Avoid

| Mistake | Fix |
|---|---|
| `supabase.from('users').select('*')` without RLS | Enable RLS + add `auth.uid() = id` policy |
| Service role key in `lib/supabase.ts` (client-side) | Move to server-only utility; use `anon` key client-side |
| `window.localStorage.setItem('token', jwt)` | Use `httpOnly` cookie or Supabase session management |
| Public storage bucket for profile images | Create signed URLs or use private bucket with server-side access |
| No input validation before `supabase.from('x').insert(req.body)` | Add Zod schema; parse before insert |
