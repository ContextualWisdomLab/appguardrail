# VibeSec: Supabase RLS Review Prompt

Use this prompt to ensure your Supabase database is securely configured.

---

**Prompt:**

I am using Supabase for this project. Please review my database schema and Row Level Security (RLS) policies.

Ensure the following security best practices are met:
1.  RLS is enabled on every table containing user data.
2.  Policies do not use the insecure `true` condition for public read/write unless explicitly intended for a public resource.
3.  Policies correctly use `auth.uid()` to restrict access to the resource owner.
4.  There is no usage of the Supabase Service Role Key in any client-side or public-facing code.

Generate the necessary SQL commands to fix any insecure policies or add missing RLS policies.
