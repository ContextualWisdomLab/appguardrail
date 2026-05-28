# Fix Authorization Bugs Prompt

Use this prompt when you have identified authorization or ownership verification gaps in your codebase. Paste it into Claude Code or Cursor along with the relevant file(s).

---

## Authorization Fix Prompt

```
This codebase has authorization vulnerabilities — specifically, missing or insufficient
ownership verification on API routes. Please fix all authorization issues following
these rules:

## Rules to Apply

1. For every API endpoint that returns user-owned resources, add this check immediately
   after authentication:
   ```
   const resource = await db.find({ where: { id: params.id } });
   if (!resource || resource.userId !== session.user.id) {
     return Response.json({ error: 'Forbidden' }, { status: 403 });
   }
   ```

2. The ownership check must happen server-side, in the API handler — not in middleware
   only, not in the frontend.

3. Return HTTP 403 (not 404, not 200 with null) for ownership violations.

4. For list endpoints, filter by the authenticated user's ID:
   ```
   const records = await db.findMany({ where: { userId: session.user.id } });
   ```
   Do NOT fetch all records and then filter in JavaScript.

5. For Supabase, ensure RLS policies enforce ownership using auth.uid():
   ```sql
   CREATE POLICY "Users can only view own records"
     ON table_name FOR SELECT
     USING (auth.uid() = user_id);
   ```

## For Each Fixed Route, Also Add These Tests:

```typescript
describe('[endpoint] authorization', () => {
  it('returns 401 when unauthenticated', async () => {
    const res = await fetch('/api/resource/some-id');
    expect(res.status).toBe(401);
  });

  it('returns 403 when authenticated user does not own the resource', async () => {
    const res = await fetch('/api/resource/other-users-id', {
      headers: { Authorization: 'Bearer ' + userBToken },
    });
    expect(res.status).toBe(403);
  });

  it('returns 200 when authenticated user owns the resource', async () => {
    const res = await fetch('/api/resource/user-a-own-id', {
      headers: { Authorization: 'Bearer ' + userAToken },
    });
    expect(res.status).toBe(200);
  });
});
```

Please review every API route, server action, and database query in this codebase and
apply these fixes consistently. List all the changes you make.
```
