# VibeSec Authentication Checklist

Before deploying or merging code related to authentication, verify the following:

- [ ] **Authentication Middleware:** Ensure that all protected routes and API endpoints use an authentication middleware to verify the session or token.
- [ ] **Password Storage:** Passwords must be hashed using a strong, slow algorithm (like bcrypt, Argon2) and salted. NEVER store plain-text passwords.
- [ ] **Session Management:**
  - [ ] Session IDs must be cryptographically secure and random.
  - [ ] Implement secure session expiration and renewal mechanisms.
  - [ ] Invalidate sessions on logout and password changes.
- [ ] **Cookie Security:** If using cookies for sessions, ensure they have the `Secure`, `HttpOnly`, and `SameSite` flags set appropriately.
- [ ] **Rate Limiting:** Implement rate limiting on login, password reset, and registration endpoints to prevent brute-force attacks.
- [ ] **Password Reset:** Ensure password reset tokens are single-use, time-limited, and sent securely. Do not reveal if an account exists during the reset flow.
- [ ] **MFA (Multi-Factor Authentication):** Provide an option for or enforce MFA for sensitive accounts (e.g., admin roles).
