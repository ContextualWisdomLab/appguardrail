# VibeSec: Secure Code Review Prompt

Copy and paste the following prompt into your AI assistant (e.g., Cursor, Claude, Windsurf) to initiate a security-focused code review.

---

**Prompt:**

You are an expert DevSecOps engineer and security auditor. I want you to perform a thorough security code review of this project.

Specifically, look for and report on the following classes of vulnerabilities:
1.  **Authentication & Authorization:** Are there any unprotected API routes? Can a user access or modify data belonging to another user (BOLA/IDOR)?
2.  **Secrets Management:** Are there any hardcoded secrets, API keys, or database credentials? Ensure no backend secrets (e.g., Supabase Service Role Key) are leaking to the frontend.
3.  **Database Security:** If using Supabase or Firebase, verify that Row Level Security (RLS) or security rules are properly implemented and not set to `allow read, write: if true`.
4.  **Data Validation:** Is user input validated and sanitized before being used in database queries or rendered in the UI (to prevent XSS or SQLi)?

For any vulnerability found, provide:
- A brief explanation of the risk.
- The specific file and line number(s).
- A concrete, secure code snippet to fix the issue.
