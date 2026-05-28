# Authentication Security Checklist

Use this checklist to verify that your vibe-coded app handles authentication correctly. AI coding tools often generate auth scaffolding that looks correct but has subtle gaps.

---

## Session Handling

- [ ] Sessions are created server-side and stored in `httpOnly`, `Secure`, `SameSite=Lax` cookies (or equivalent).
- [ ] Session tokens are never stored in `localStorage` or `sessionStorage` for sensitive apps.
- [ ] Session lifetime is reasonable (e.g., 7 days max for standard apps, 1 hour for sensitive operations).
- [ ] On logout, the session is invalidated server-side (not just removed from the client).
- [ ] "Remember me" functionality extends the session properly without weakening security.

## Login Flow

- [ ] Login validates credentials server-side. No client-side bypass is possible.
- [ ] Login rate-limiting or lockout is in place (prevent brute-force).
- [ ] Error messages are generic: "Invalid email or password" — not "Email not found" or "Wrong password."
- [ ] Account enumeration through timing differences is mitigated.
- [ ] MFA is supported for sensitive accounts (admin, billing, etc.).

## Signup / Registration

- [ ] Email verification is required before the account can perform sensitive actions.
- [ ] Passwords are hashed server-side with a strong algorithm (bcrypt, Argon2, scrypt).
- [ ] Passwords are never stored in plaintext or with weak hashing (MD5, SHA1).
- [ ] Password strength requirements are enforced server-side (not just in the UI).

## Password Reset

- [ ] Password reset tokens are cryptographically random and sufficiently long (≥ 32 bytes).
- [ ] Password reset tokens expire (e.g., within 1 hour).
- [ ] Password reset tokens are single-use (invalidated after use).
- [ ] The reset endpoint verifies the token before accepting a new password.
- [ ] Old sessions are invalidated after a password change.

## OAuth / Social Login

- [ ] The `state` parameter is validated to prevent CSRF attacks in the OAuth flow.
- [ ] Redirect URIs are whitelisted; open redirect is not possible.
- [ ] The `access_token` from the provider is verified server-side, not just trusted from the client.
- [ ] Account linking (connecting multiple providers to one account) is handled securely.

## Supabase Auth Specifics

- [ ] `supabase.auth.getUser()` (not `getSession()`) is used server-side to validate the user.
- [ ] JWT secret is not hardcoded; it comes from Supabase's managed secret.
- [ ] RLS policies depend on `auth.uid()`, not on client-supplied user IDs.
- [ ] Service role key is never used client-side or in public code.

## Common AI-Generated Auth Mistakes

| Mistake | Why It's Dangerous |
|---|---|
| `// TODO: add auth check later` | Left as-is in production → full data exposure |
| `if (user) { ... }` checked only in middleware | API routes remain unprotected if middleware is bypassed |
| Trusting `user.id` from the request body | Attacker can set any user ID |
| Storing JWT in `localStorage` | XSS can steal the token |
| Not invalidating sessions on logout | Old tokens remain valid |
| Using `getSession()` server-side in Supabase | Returns unverified client-side data |
