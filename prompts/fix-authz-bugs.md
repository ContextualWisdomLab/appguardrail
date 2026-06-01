# VibeSec: Fix Authorization Bugs Prompt

Use this prompt when you suspect or have identified authorization bypass issues (BOLA/IDOR) in your AI-generated app.

---

**Prompt:**

Act as an application security engineer. I need you to review all data fetching and mutation endpoints (API routes, server actions, etc.) in this codebase.

Your goal is to enforce strict **Resource Ownership Authorization**.

1.  Identify every endpoint that receives an ID (e.g., `project_id`, `user_id`, `document_id`) from the client.
2.  Check if the endpoint verifies that the currently authenticated user actually *owns* or has permission to access that specific resource ID.
3.  If an endpoint blindly queries the database using the provided ID without an ownership check, it is vulnerable.

Please rewrite the vulnerable endpoints to include ownership checks (e.g., `where owner_id = current_user_id`). Ensure the endpoint returns an HTTP 403 Forbidden status if the check fails.
