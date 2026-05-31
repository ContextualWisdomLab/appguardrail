# ⚠️ WARNING: Intentionally Vulnerable Application

**This is a demonstration of insecure code patterns for educational purposes.**
**DO NOT deploy this to a public URL. DO NOT use real credentials.**

This example shows common security mistakes in AI-generated Next.js + Supabase apps.
See `../fixed-vibe-app/` for the corrected version.

---

## Vulnerabilities Demonstrated

### 1. Missing Ownership Check (IDOR)

`app/api/projects/[id]/route.ts`

```typescript
// ❌ VULNERABLE: No ownership check — any user can access any project
export async function GET(
  req: Request,
  { params }: { params: { id: string } }
) {
  const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  );

  // No authentication check!
  // No ownership verification!
  const { data, error } = await supabase
    .from('projects')
    .select('*')
    .eq('id', params.id)
    .single();

  return Response.json(data);
}
```

**Impact:** Any user (authenticated or not) can read any project by guessing or iterating project IDs.

---

### 2. Service Role Key Exposed Client-Side

`lib/supabase.ts`

```typescript
// ❌ VULNERABLE: Service role key used in a file that can be imported by client components
import { createClient } from '@supabase/supabase-js';

export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY! // exposed in browser bundle!
);
```

**Impact:** The service role key is bundled into client-side JavaScript. Any user can extract it and gain full database access, bypassing all RLS policies.

---

### 3. No Stripe Webhook Verification

`app/api/webhooks/stripe/route.ts`

```typescript
// ❌ VULNERABLE: No signature verification
export async function POST(req: Request) {
  const event = await req.json(); // trusting the body directly!

  if (event.type === 'checkout.session.completed') {
    // Attacker can POST a fake 'checkout.session.completed' event
    // and get any account upgraded to Pro for free
    await db.user.update({
      where: { stripeCustomerId: event.data.object.customer },
      data: { plan: 'pro' },
    });
  }

  return Response.json({ received: true });
}
```

**Impact:** An attacker can send a fake webhook event to upgrade their account (or anyone's account) to Pro without paying.

---

### 4. Price Taken from Client

`app/api/checkout/route.ts`

```typescript
// ❌ VULNERABLE: Price ID comes from the client
export async function POST(req: Request) {
  const { priceId } = await req.json(); // attacker controls this!

  const session = await stripe.checkout.sessions.create({
    line_items: [{ price: priceId, quantity: 1 }], // price from attacker!
    mode: 'subscription',
    success_url: `${process.env.NEXT_PUBLIC_URL}/success`,
    cancel_url: `${process.env.NEXT_PUBLIC_URL}/pricing`,
  });

  return Response.json({ url: session.url });
}
```

**Impact:** An attacker can supply a price ID for a cheaper plan (or a free trial) and bypass payment.

---

### 5. Hardcoded Secret

`lib/db.ts`

```typescript
// ❌ VULNERABLE: Hardcoded database URL
const db = new PrismaClient({
  datasources: {
    db: {
      url: '******db.example.com:5432/myapp',
    },
  },
});
```

**Impact:** Anyone with read access to the repository can connect to the database directly.

---

### 6. Supabase RLS Disabled

`supabase/migrations/001_initial.sql`

```sql
-- ❌ VULNERABLE: RLS never enabled, no policies
CREATE TABLE projects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id),
  name TEXT,
  data JSONB
);

-- Missing: ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
-- Missing: CREATE POLICY ... USING (auth.uid() = user_id);
```

**Impact:** Any authenticated user can read, modify, or delete any row in the `projects` table via the Supabase client.

---

### 7. TODO Auth Bypass

`app/api/admin/users/route.ts`

```typescript
// ✅ SECURE: Admin role verified server-side
import { auth } from '@/auth';

export async function GET(req: Request) {
  const session = await auth();

  // Step 1: Require authentication
  if (!session) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Step 2: Require admin role (from database, not just session claim)
  const user = await db.user.findUnique({
    where: { id: session.user.id },
    select: { role: true },
  });

  if (user?.role !== 'admin') {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

  const users = await db.user.findMany({
    select: { id: true, email: true, createdAt: true, plan: true },
    // Never include passwords, secrets, or sensitive fields
  });

  return Response.json(users);
}
```

**Impact:** Previously, the `/api/admin/users` endpoint was publicly accessible and returned all user records. It is now secured.

---

## How to Run (For Testing Only)

```bash
# Install dependencies
npm install

# Copy .env.example and fill in TEST values only
cp .env.example .env.local

# Run development server
npm run dev
```

> **Never use real credentials. Never deploy this app.**

---

## See the Fixed Version

All of these vulnerabilities are fixed in `../fixed-vibe-app/`. Compare the two to understand each fix.
