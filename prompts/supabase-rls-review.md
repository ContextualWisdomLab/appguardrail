# Supabase RLS Review Prompt

Use this prompt to audit and fix Supabase Row Level Security policies in your project.

---

## Supabase RLS Audit Prompt

```
Please perform a complete audit of the Supabase Row Level Security (RLS) configuration
in this project and fix any issues found.

## Step 1: Identify All Tables

List every Supabase table in this project. For each table, determine:
- Does it store user-specific data?
- Is RLS currently enabled?
- What policies exist?

## Step 2: Enable RLS on All User-Data Tables

For any table that stores data belonging to users, ensure RLS is enabled:
```sql
ALTER TABLE table_name ENABLE ROW LEVEL SECURITY;
```

## Step 3: Create Correct Policies

For each user-data table, create policies following this pattern:

```sql
-- SELECT: users can only read their own rows
CREATE POLICY "Users can view own [table]"
  ON table_name FOR SELECT
  USING (auth.uid() = user_id);

-- INSERT: users can only create rows owned by themselves
CREATE POLICY "Users can create own [table]"
  ON table_name FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- UPDATE: users can only update their own rows
CREATE POLICY "Users can update own [table]"
  ON table_name FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- DELETE: users can only delete their own rows
CREATE POLICY "Users can delete own [table]"
  ON table_name FOR DELETE
  USING (auth.uid() = user_id);
```

Replace `user_id` with the actual column name that stores the owner's user ID.

## Step 4: Fix Dangerous Patterns

Look for and fix these dangerous patterns in application code:

1. **service_role key used client-side:**
   - Find any file that imports SUPABASE_SERVICE_ROLE_KEY
   - Move that logic to a server-side API route or server action
   - Replace with the anon key + RLS for client-side operations

2. **Bypassing RLS with service role unnecessarily:**
   - Check if service role is used where RLS + anon key would suffice
   - Limit service role usage to genuine admin operations

3. **Using getSession() server-side:**
   - Replace with getUser() which validates the JWT server-side

## Step 5: Verify with Test Queries

Write SQL to test that RLS is working:
```sql
-- Test as an authenticated user
SET LOCAL role = authenticated;
SET LOCAL request.jwt.claims = '{"sub": "user-a-uuid"}';

-- This should only return rows where user_id = 'user-a-uuid'
SELECT * FROM table_name;

-- This should return 0 rows (user A cannot see user B's data)
SELECT * FROM table_name WHERE user_id = 'user-b-uuid';
```

Please list every table, its current RLS status, any issues found, and all changes made.
```
