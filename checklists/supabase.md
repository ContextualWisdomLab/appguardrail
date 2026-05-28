# Supabase Security Checklist

Supabase is the most popular backend for vibe-coded apps. These are the most common Supabase security mistakes and how to fix them.

---

## Row Level Security (RLS)

- [ ] RLS is **enabled** on every table that stores user data.
  ```sql
  ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
  ALTER TABLE files ENABLE ROW LEVEL SECURITY;
  -- repeat for every user-data table
  ```
- [ ] Every table has explicit policies for SELECT, INSERT, UPDATE, and DELETE.
- [ ] Policies use `auth.uid()` to bind rows to their owner.
  ```sql
  CREATE POLICY "Users can view own projects"
    ON projects FOR SELECT
    USING (auth.uid() = user_id);

  CREATE POLICY "Users can create own projects"
    ON projects FOR INSERT
    WITH CHECK (auth.uid() = user_id);
  ```
- [ ] No table has `USING (true)` or `WITH CHECK (true)` in production (opens all rows to all users).
- [ ] The `public` schema does not have overly permissive grants.
- [ ] Tables intended to be public (e.g., blog posts) have deliberate policies, not missing policies.

## Client vs Service Role Keys

- [ ] The `anon` key is used in the browser and client components.
- [ ] The `service_role` key is **never** imported in:
  - Client components (`*.tsx`, `*.jsx` with `'use client'`)
  - Hooks (`use*.ts`)
  - Any file that could be bundled for the browser
- [ ] The `service_role` key is only used in:
  - Server Actions (`'use server'`)
  - API Routes (`/api/**`)
  - Edge Functions
  - Scripts that run locally
- [ ] `SUPABASE_SERVICE_ROLE_KEY` does not use `NEXT_PUBLIC_` prefix.

## Authentication

- [ ] `supabase.auth.getUser()` is used server-side (not `getSession()` — it does not validate the JWT).
- [ ] Email confirmation is enabled in the Supabase Auth settings for production.
- [ ] Redirect URLs in Supabase Auth are allowlisted to prevent open redirect.
- [ ] OAuth providers are configured with production redirect URLs (not localhost).

## Storage

- [ ] Buckets that hold private user files are set to **private** (not public).
- [ ] Access to private files is through signed URLs generated server-side.
- [ ] Storage policies enforce ownership:
  ```sql
  CREATE POLICY "Users can upload own files"
    ON storage.objects FOR INSERT
    WITH CHECK (auth.uid()::text = (storage.foldername(name))[1]);
  ```
- [ ] File size limits are configured in the Supabase Storage settings.
- [ ] MIME type restrictions are enforced.

## Database Functions & RPCs

- [ ] `SECURITY DEFINER` functions are reviewed carefully — they bypass RLS.
- [ ] Input parameters to database functions are validated and sanitized.
- [ ] Functions are not exposed publicly if they perform privileged operations.

## Common Supabase Mistakes in AI-Generated Code

| Mistake | Fix |
|---|---|
| `createClient(url, serviceRoleKey)` in a client component | Use `anon` key client-side; service role server-only |
| No RLS on `users` or `profiles` table | Enable RLS + add `auth.uid() = id` policy |
| `supabase.from('users').select('*')` returns all users | Add SELECT policy; use RLS to filter |
| Public storage bucket for profile photos | Private bucket + signed URL |
| `getSession()` used server-side to verify auth | Use `getUser()` which validates the JWT |
| `SUPABASE_SERVICE_ROLE_KEY` in `.env.local` committed to git | Add `.env.local` to `.gitignore` |
