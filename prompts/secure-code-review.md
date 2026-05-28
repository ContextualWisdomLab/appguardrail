# Secure Code Review Prompt

Copy this prompt into Claude Code, Cursor, or any AI coding assistant to perform a comprehensive security review of your codebase.

---

## Full Security Review Prompt

```
Please perform a comprehensive security review of this codebase. Focus on vulnerabilities
that are common in AI-generated web applications built with modern stacks
(Next.js, Supabase, Firebase, Stripe, Vercel).

Review the following areas:

## 1. Authentication Gaps
- Are there any API routes or server actions missing authentication checks?
- Is session validation done server-side using a secure method?
- Are there any routes where the authentication check comes after data access?

## 2. Authorization & Ownership
- For every endpoint that returns or modifies user-owned resources, is ownership
  verified server-side before the data is returned or modified?
- Can a user access another user's data by changing an ID in the URL or request body?
- Are admin routes protected by role checks, not just authentication?

## 3. Secrets & Environment Variables
- Are there any hardcoded API keys, passwords, or tokens in the source code?
- Are any secret environment variables prefixed with NEXT_PUBLIC_ (which would
  expose them to the browser)?
- Is SUPABASE_SERVICE_ROLE_KEY or any admin key used in client-side code?

## 4. Supabase / Firebase Misconfigurations
- Is Row Level Security (RLS) enabled on all tables?
- Do RLS policies correctly use auth.uid() to enforce ownership?
- Are there any Firestore rules set to allow read, write: if true?
- Is the service role key used only in server-side code?

## 5. Input Validation
- Is user input validated server-side before being used in database queries or
  other operations?
- Is there any risk of SQL injection or NoSQL injection?
- Are file uploads validated for type, size, and filename on the server?

## 6. Stripe & Payments
- Is the Stripe webhook signature verified using stripe.webhooks.constructEvent?
- Are prices fetched server-side, not taken from the client?
- Is the billing management portal protected by both auth and ownership checks?

## 7. AI-Generated Code Patterns
- Are there any TODO comments that disable or defer security checks?
- Is there any mock authentication or placeholder access control left in the code?
- Are there any commented-out security checks or hardcoded test credentials?

## 8. CORS & Security Headers
- Is CORS set to allow all origins on authenticated endpoints?
- Are security headers (CSP, X-Frame-Options, etc.) configured?

For each issue found, provide:
1. The file and line number
2. A description of the vulnerability
3. The risk if exploited
4. A specific code fix
5. A test case to verify the fix
```
