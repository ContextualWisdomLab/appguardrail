# Secrets & Environment Variables Security Checklist

Hardcoded or leaked secrets are among the most common and most damaging vulnerabilities in vibe-coded apps.

---

## What Counts as a Secret

The following must **never** appear in source code, client-side bundles, or public repositories:

- Database connection strings (`DATABASE_URL`, `POSTGRES_URL`, etc.)
- API secret keys (`STRIPE_SECRET_KEY`, `OPENAI_API_KEY`, etc.)
- Supabase Service Role Key (`SUPABASE_SERVICE_ROLE_KEY`)
- Firebase service account credentials
- JWT signing secrets (`JWT_SECRET`, `NEXTAUTH_SECRET`)
- SMTP credentials
- Private signing keys or certificates
- OAuth client secrets
- Admin passwords or internal tool tokens

---

## Environment Variables

- [ ] All secrets are stored in environment variables, never hardcoded in source files.
- [ ] `.env`, `.env.local`, `.env.production`, `.env.development` are listed in `.gitignore`.
- [ ] A `.env.example` file (with placeholder values, no real secrets) is committed to the repo.
- [ ] Production secrets are set in the hosting platform's environment settings (Vercel, Netlify, Railway, etc.) — not in committed files.

## Client-Side Exposure

- [ ] Secrets do not use `NEXT_PUBLIC_` prefix (which would bundle them into the client).
- [ ] No secret is imported in a component file, hook, or any file in the `app/` directory outside of server-only routes/actions.
- [ ] Browser bundle is inspected to confirm no secrets are present (check the `.next/static/chunks` output).
- [ ] `server-only` package (Next.js) is used to prevent accidental imports of server-only modules in client components.

```typescript
// At the top of a server-only utility file
import 'server-only';
```

## Git History

- [ ] Git history is scanned for accidentally committed secrets (use `git log -p | grep -i "key\|secret\|password"`).
- [ ] If a secret was ever committed, it has been **rotated** — removing it from git history alone is not sufficient.
- [ ] `git-secrets`, `truffleHog`, or `gitleaks` has been run on the repository.

## Third-Party Integrations

- [ ] Each third-party API key has the minimum required permissions (principle of least privilege).
- [ ] API keys are rotated periodically and after any suspected exposure.
- [ ] Webhook secrets are unique per endpoint and per environment.

## Supabase-Specific

- [ ] `SUPABASE_SERVICE_ROLE_KEY` is server-side only (no `NEXT_PUBLIC_` prefix).
- [ ] The Supabase `anon` key (which is `NEXT_PUBLIC_SUPABASE_ANON_KEY`) is the only Supabase key in client-side code.
- [ ] RLS is enabled to limit what the `anon` key can access.

## Common Secrets Mistakes in AI-Generated Code

| Mistake | Fix |
|---|---|
| `const apiKey = "sk-..."` in source code | Move to environment variable |
| `NEXT_PUBLIC_STRIPE_SECRET_KEY` | Remove `NEXT_PUBLIC_` prefix |
| `.env.local` committed to git | Add to `.gitignore`; rotate all exposed secrets |
| Secrets logged with `console.log(process.env)` | Remove logging of env vars |
| Same secrets in dev and production | Use separate keys per environment |
| API key with full admin access | Create a restricted key with only required permissions |
