# VibeSec Cursor Security Rules

When writing or modifying code using Cursor, ALWAYS adhere to the following security principles:

1. **Enforce Authentication & Ownership:** When generating API routes, always enforce authentication and ownership checks.
2. **Server-Side Authorization:** Never rely on frontend-only authorization. Always verify permissions on the server.
3. **Protect Secrets:** Never expose service role keys, database URLs with passwords, or other secrets to client-side code.
4. **Verify Resource Ownership:** For every user-owned resource, verify the `owner_id` (or equivalent) against the current authenticated session user.
5. **Test Access Denial:** Add tests specifically designed to verify that cross-user access is denied (e.g., User A cannot read User B's data).
