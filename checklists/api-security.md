# API Security Checklist

API routes are the most critical attack surface in vibe-coded apps. This checklist covers the full lifecycle of a secure API.

---

## Authentication on Every Route

- [ ] Every protected API route checks authentication as the **first** operation.
- [ ] The check is done server-side, not delegated entirely to middleware that can be bypassed.
- [ ] Routes return `401 Unauthorized` for unauthenticated requests with no data leakage.
- [ ] Authentication logic uses the framework's built-in session/auth utilities, not custom JWT parsing.

```typescript
// Next.js App Router example
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await auth(); // or getServerSession(authOptions)
  if (!session) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  // ... rest of handler
}
```

## Authorization / Ownership

- [ ] Every endpoint that returns or modifies a specific resource verifies the caller owns it.
- [ ] See [authorization.md](authorization.md) for the full ownership checklist.

## Input Validation

- [ ] All inputs (path params, query strings, request bodies) are validated with a schema.
- [ ] Unknown/extra fields are stripped from the request before processing.
- [ ] Validation errors return `400 Bad Request` with a useful message (but no internal details).

```typescript
const schema = z.object({
  name: z.string().min(1).max(100),
  projectId: z.string().uuid(),
});
const result = schema.safeParse(await req.json());
if (!result.success) return Response.json({ error: result.error.flatten() }, { status: 400 });
```

## HTTP Method Handling

- [ ] Endpoints accept only the HTTP methods they are designed for.
- [ ] `GET` requests do not perform mutations (no side effects on GET).
- [ ] `DELETE` requests require the resource ID and an ownership check — not just a body flag.

## Rate Limiting

- [ ] Authentication endpoints (login, signup, password reset, OTP) are rate-limited.
- [ ] Resource-intensive endpoints are rate-limited per user or IP.
- [ ] Rate limits are enforced server-side (middleware or edge function), not client-side.

## Error Handling

- [ ] Error responses do not expose stack traces, database errors, or internal implementation details.
- [ ] Error messages are user-facing and generic: "An error occurred" rather than "PG: relation 'users' does not exist."
- [ ] Logging captures the full error server-side for debugging.
- [ ] Unexpected errors return `500 Internal Server Error` without leaking sensitive data.

## CORS

- [ ] CORS is not set to `Access-Control-Allow-Origin: *` on routes that handle authenticated sessions.
- [ ] Allowed origins are an explicit allowlist of known domains.
- [ ] Preflight requests (`OPTIONS`) are handled correctly.

```typescript
// next.config.js
async headers() {
  return [{
    source: '/api/:path*',
    headers: [
      { key: 'Access-Control-Allow-Origin', value: 'https://yourdomain.com' },
      { key: 'Access-Control-Allow-Methods', value: 'GET,POST,PUT,DELETE,OPTIONS' },
    ],
  }];
}
```

## Sensitive Data in Responses

- [ ] API responses do not include password hashes, secret keys, or internal IDs that aren't needed.
- [ ] User objects returned from APIs are filtered to include only what the client needs.
- [ ] Admin-only fields are excluded from regular user responses.

## Common API Security Mistakes in AI-Generated Code

| Mistake | Fix |
|---|---|
| Auth check after DB query | Move auth check to the top of the handler |
| `req.body` passed directly to `db.create()` | Validate and destructure only allowed fields |
| `console.log(err)` exposing stack to response | Log server-side; return generic message to client |
| All HTTP methods allowed on a route | Explicitly handle only required methods |
| No rate limiting on `/api/auth/login` | Add rate limiting middleware |
| `origin: '*'` with `credentials: true` | Browsers block this; use specific origin |
