# Authorization & Ownership Security Checklist

Authorization bugs are the most common and most critical issue in vibe-coded apps. AI tools typically generate authentication but frequently miss ownership enforcement — every user can access every other user's data.

---

## Core Principle

**Authentication** answers: "Who are you?"
**Authorization** answers: "Are you allowed to do this to this specific resource?"

Most vibe-coded apps get authentication right. Authorization is where they fail.

---

## Resource Ownership Checks

- [ ] Every API endpoint that returns user-specific data verifies `resource.ownerId === session.user.id`.
- [ ] Every API endpoint that mutates user-specific data verifies ownership before applying the change.
- [ ] The verification happens **server-side** — not just in the UI or middleware.
- [ ] Resources are not exposed simply because the user is authenticated; they must also own them.
- [ ] `403 Forbidden` is returned for ownership violations, not `404` or `200 null`.

## Insecure Direct Object Reference (IDOR)

- [ ] Changing a resource ID in the URL or request body does **not** expose another user's data.
- [ ] Test: log in as User A, copy a resource URL, log in as User B, visit that URL → should get `403`.
- [ ] Numeric or sequential IDs are not used as the only access control (use UUIDs + ownership checks).
- [ ] Bulk endpoints (list all X) filter by the authenticated user's ID, not return everything.

## Role-Based Access Control (RBAC)

- [ ] Admin routes (`/admin/*`, `/dashboard/admin`, etc.) check for an `admin` role, not just authentication.
- [ ] Role assignments are stored and verified server-side; the client cannot elevate its own role.
- [ ] Privileged operations (ban user, delete any record, access all data) are gated behind explicit role checks.
- [ ] Role checks are not bypassable by manipulating request parameters.

## Multi-Tenant Applications

- [ ] Data is scoped to the correct `organizationId` / `teamId` / `workspaceId` on every query.
- [ ] Users cannot switch between organizations by changing an ID in the request.
- [ ] Invitation flows validate that the inviting user has permission to invite to that organization.
- [ ] Cross-tenant data leakage is tested explicitly.

## Supabase RLS as Authorization Layer

- [ ] Row Level Security is enabled on every table: `ALTER TABLE x ENABLE ROW LEVEL SECURITY`.
- [ ] SELECT policy: `USING (auth.uid() = user_id)`.
- [ ] INSERT policy: `WITH CHECK (auth.uid() = user_id)`.
- [ ] UPDATE policy: `USING (auth.uid() = user_id)`.
- [ ] DELETE policy: `USING (auth.uid() = user_id)`.
- [ ] Admin/service role operations bypass RLS intentionally and are isolated to server-only code.
- [ ] RLS policies are tested with `SET ROLE authenticated; SET LOCAL request.jwt.claim.sub = 'user-id';` style tests.

## Authorization Anti-Patterns in AI-Generated Code

| Anti-Pattern | Correct Pattern |
|---|---|
| `db.find({ id: req.params.id })` | `db.find({ id: req.params.id, userId: session.user.id })` |
| Frontend hides admin button → no server check | Server checks `user.role === 'admin'` on every admin request |
| `if (req.body.isAdmin) { ... }` | Fetch role from DB; never trust client-supplied role |
| Supabase table with no RLS policies | Add policies for SELECT/INSERT/UPDATE/DELETE |
| Returning `404` on ownership violation | Return `403` to avoid leaking resource existence |

## Test Cases to Add

```
describe('authorization', () => {
  it('returns 403 when User A tries to access User B project', async () => {
    const res = await request(app)
      .get('/api/projects/' + userBProjectId)
      .set('Authorization', 'Bearer ' + userAToken);
    expect(res.status).toBe(403);
  });

  it('returns 403 when User A tries to delete User B record', async () => {
    const res = await request(app)
      .delete('/api/records/' + userBRecordId)
      .set('Authorization', 'Bearer ' + userAToken);
    expect(res.status).toBe(403);
  });
});
```
