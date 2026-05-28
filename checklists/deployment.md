# Deployment Security Checklist

Deployment is the last line of defense before your app goes live. AI-generated apps often focus on functionality and skip deployment hardening.

---

## Environment Configuration

- [ ] All production environment variables are set in the hosting platform dashboard, not in committed files.
- [ ] `NODE_ENV=production` is set in production environments.
- [ ] Debug modes, verbose logging, and development tools are disabled in production.
- [ ] Source maps are not publicly exposed (or are restricted to authenticated error-tracking services).

## HTTPS

- [ ] HTTPS is enforced for all traffic. HTTP requests are redirected to HTTPS.
- [ ] SSL certificate is valid and auto-renews (managed by the hosting platform or Let's Encrypt).
- [ ] HSTS (HTTP Strict Transport Security) is enabled with a suitable `max-age`.
  ```
  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
  ```

## Security Headers

- [ ] `Content-Security-Policy` is configured to restrict script, style, and media sources.
- [ ] `X-Frame-Options: DENY` (or `SAMEORIGIN`) prevents clickjacking.
- [ ] `X-Content-Type-Options: nosniff` prevents MIME sniffing.
- [ ] `Referrer-Policy: strict-origin-when-cross-origin` limits referrer leakage.
- [ ] `Permissions-Policy` restricts browser features (camera, microphone, geolocation) to what is needed.

```javascript
// next.config.js
async headers() {
  return [{
    source: '/(.*)',
    headers: [
      { key: 'X-Frame-Options', value: 'DENY' },
      { key: 'X-Content-Type-Options', value: 'nosniff' },
      { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
      { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
    ],
  }];
}
```

## Public Exposure

- [ ] Only the frontend and intended public API routes are exposed.
- [ ] Admin panels, debug endpoints, and health-check endpoints that expose internals are protected or restricted to internal IPs.
- [ ] Directory listing is disabled.
- [ ] `.env`, `.git`, `package.json`, and other internal files are not accessible via HTTP.
- [ ] Error pages do not expose stack traces, server software versions, or internal paths.

## Dependency Security

- [ ] `npm audit` (or equivalent) is run before deploying. Critical and high-severity vulnerabilities are resolved.
- [ ] Dependencies are pinned to specific versions in `package-lock.json` / `yarn.lock`.
- [ ] Lockfiles are committed to the repository.
- [ ] Dependencies are reviewed periodically for vulnerabilities and updates.

## Storage & Data

- [ ] Storage buckets are private by default; only explicitly public assets use a public bucket.
- [ ] Database backups are enabled and tested.
- [ ] Database connection uses SSL.
- [ ] Database is not directly accessible from the public internet (use connection pooling + VPC if possible).

## Monitoring & Incident Response

- [ ] Error monitoring (Sentry, Axiom, etc.) is configured for production.
- [ ] Alerting is set up for unusual error rates or authentication failures.
- [ ] A basic incident response plan exists (who to contact, how to rotate keys, how to roll back).

## Common Deployment Mistakes in AI-Generated Apps

| Mistake | Fix |
|---|---|
| `.env.production` committed to git | Add to `.gitignore`; use platform env vars |
| No security headers | Add headers in `next.config.js` or middleware |
| Debug endpoint `/api/debug` exposed in production | Remove or restrict to internal network |
| `npm audit` skipped | Run before every deploy; fix critical issues |
| Same database for dev and production | Use separate databases per environment |
| No error monitoring | Add Sentry or equivalent before launch |
