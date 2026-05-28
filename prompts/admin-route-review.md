# Admin Route Security Review Prompt

Use this prompt to audit and fix admin route access controls in your project.

---

## Admin Route Audit Prompt

```
Please review and fix all admin routes, admin pages, and privileged operations
in this codebase to ensure they are properly protected.

## Step 1: Identify All Admin Surfaces

Find every admin route, page, and API endpoint in this codebase. Look for:
- Routes with /admin/ in the path
- Pages or APIs that allow reading all users' data
- Endpoints that allow deleting or modifying any user's records
- Dashboard or analytics pages that aggregate all user data
- User management features (ban, promote, delete users)

## Step 2: Verify Role Checks

For every admin surface, ensure there is an explicit role check:

```typescript
// Next.js App Router
const session = await auth();
if (!session) return redirect('/login');
if (session.user.role !== 'admin') {
  return Response.json({ error: 'Forbidden' }, { status: 403 });
}
```

Do NOT rely solely on:
- Hiding the link in the UI (UI-only protection)
- Checking isAdmin from req.body or req.query (attacker can set this)
- Middleware-only protection (middleware can be bypassed for API routes)

## Step 3: Verify Role Storage

Ensure roles are stored and verified securely:
- Roles must be stored in the database, not only in the JWT/session
- If roles are in the JWT, they must be re-verified against the database for
  high-privilege operations
- Users cannot elevate their own role via an API call

For Supabase, add a server-side role check:
```typescript
const { data: profile } = await supabaseAdmin
  .from('profiles')
  .select('role')
  .eq('id', session.user.id)
  .single();

if (profile?.role !== 'admin') {
  return Response.json({ error: 'Forbidden' }, { status: 403 });
}
```

## Step 4: Audit Supabase Admin Policies

For tables with admin access:
```sql
-- Admins can read all rows; regular users can only see their own
CREATE POLICY "Admins can view all, users view own"
  ON table_name FOR SELECT
  USING (
    auth.uid() = user_id
    OR EXISTS (
      SELECT 1 FROM profiles
      WHERE profiles.id = auth.uid()
      AND profiles.role = 'admin'
    )
  );
```

## Step 5: Add Tests for Admin Routes

```typescript
describe('admin routes', () => {
  it('returns 401 when unauthenticated', async () => {
    const res = await fetch('/api/admin/users');
    expect(res.status).toBe(401);
  });

  it('returns 403 when authenticated as non-admin', async () => {
    const res = await fetch('/api/admin/users', {
      headers: { Authorization: 'Bearer ' + regularUserToken },
    });
    expect(res.status).toBe(403);
  });

  it('returns 200 when authenticated as admin', async () => {
    const res = await fetch('/api/admin/users', {
      headers: { Authorization: 'Bearer ' + adminToken },
    });
    expect(res.status).toBe(200);
  });
});
```

List all admin surfaces found, their current protection status, and all changes made.
```
