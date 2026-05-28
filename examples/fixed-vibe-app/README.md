# ✅ Fixed Vibe App

**This is the secure version of the vulnerable example.**

See `../vulnerable-vibe-app/README.md` for the list of vulnerabilities that were fixed.

---

## Security Fixes Applied

### 1. Ownership Check Added (IDOR Fixed)

`app/api/projects/[id]/route.ts`

```typescript
// ✅ SECURE: Authentication + ownership verification
import { auth } from '@/auth';
import { createClient } from '@/lib/supabase/server';

export async function GET(
  req: Request,
  { params }: { params: { id: string } }
) {
  // Step 1: Check authentication
  const session = await auth();
  if (!session) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const supabase = createClient();

  // Step 2: Fetch the project
  const { data: project, error } = await supabase
    .from('projects')
    .select('*')
    .eq('id', params.id)
    .single();

  // Step 3: Verify ownership
  if (error || !project || project.user_id !== session.user.id) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

  return Response.json(project);
}
```

**Fix:** Authentication check + server-side ownership verification. Returns 403 (not 404) on ownership violation.

---

### 2. Service Role Key Secured

`lib/supabase/server.ts` (server-only)

```typescript
// ✅ SECURE: Service role client is server-only
import 'server-only'; // prevents import in client components
import { createClient } from '@supabase/supabase-js';

// This file can only be imported by server-side code
export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY! // no NEXT_PUBLIC_ prefix!
);
```

`lib/supabase/client.ts` (browser)

```typescript
// ✅ SECURE: Client uses anon key only
import { createBrowserClient } from '@supabase/ssr';

export function createClient() {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY! // anon key only
  );
}
```

---

### 3. Stripe Webhook Verification Added

`app/api/webhooks/stripe/route.ts`

```typescript
// ✅ SECURE: Signature verified before processing
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const rawBody = await req.text(); // raw body for signature verification
  const sig = req.headers.get('stripe-signature')!;

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(
      rawBody,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
  } catch (err) {
    console.error('Webhook signature verification failed:', err);
    return Response.json({ error: 'Invalid signature' }, { status: 400 });
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object as Stripe.Checkout.Session;
    await db.user.update({
      where: { stripeCustomerId: session.customer as string },
      data: { plan: 'pro' },
    });
  }

  return Response.json({ received: true });
}
```

---

### 4. Price Fetched Server-Side

`app/api/checkout/route.ts`

```typescript
// ✅ SECURE: Price ID comes from environment, not the client
import { auth } from '@/auth';
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

// Price IDs are defined server-side only
const PRICE_IDS = {
  pro_monthly: process.env.STRIPE_PRICE_ID_PRO_MONTHLY!,
  pro_annual: process.env.STRIPE_PRICE_ID_PRO_ANNUAL!,
} as const;

export async function POST(req: Request) {
  const session = await auth();
  if (!session) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { plan } = await req.json();

  // Look up the price server-side — never from client
  const priceId = PRICE_IDS[plan as keyof typeof PRICE_IDS];
  if (!priceId) {
    return Response.json({ error: 'Invalid plan' }, { status: 400 });
  }

  const checkoutSession = await stripe.checkout.sessions.create({
    customer_email: session.user.email!,
    line_items: [{ price: priceId, quantity: 1 }],
    mode: 'subscription',
    success_url: `${process.env.NEXT_PUBLIC_URL}/success`,
    cancel_url: `${process.env.NEXT_PUBLIC_URL}/pricing`,
  });

  return Response.json({ url: checkoutSession.url });
}
```

---

### 5. Secret Moved to Environment Variable

`.env.local` (not committed)

```
DATABASE_URL=******db.example.com:5432/myapp
```

`.env.example` (committed, with placeholder)

```
DATABASE_URL=******host:5432/dbname
```

`lib/db.ts`

```typescript
// ✅ SECURE: URL from environment variable
const db = new PrismaClient(); // uses DATABASE_URL from process.env automatically
```

---

### 6. Supabase RLS Enabled

`supabase/migrations/001_initial.sql`

```sql
-- ✅ SECURE: RLS enabled with proper policies
CREATE TABLE projects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) NOT NULL,
  name TEXT NOT NULL,
  data JSONB
);

-- Enable Row Level Security
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;

-- Users can only see their own projects
CREATE POLICY "Users can view own projects"
  ON projects FOR SELECT
  USING (auth.uid() = user_id);

-- Users can only create projects owned by themselves
CREATE POLICY "Users can create own projects"
  ON projects FOR INSERT
  WITH CHECK (auth.uid() = user_id);

-- Users can only update their own projects
CREATE POLICY "Users can update own projects"
  ON projects FOR UPDATE
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Users can only delete their own projects
CREATE POLICY "Users can delete own projects"
  ON projects FOR DELETE
  USING (auth.uid() = user_id);
```

---

### 7. Admin Auth Check Added

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

---

## Security Tests

Each fixed endpoint has corresponding tests:

```typescript
describe('GET /api/projects/[id]', () => {
  it('returns 401 when unauthenticated', async () => {
    const res = await GET(request('/api/projects/test-id'));
    expect(res.status).toBe(401);
  });

  it('returns 403 when accessing another user\\'s project', async () => {
    mockSession({ user: { id: 'user-a' } });
    const res = await GET(request('/api/projects/user-b-project-id'));
    expect(res.status).toBe(403);
  });

  it('returns 200 for the project owner', async () => {
    mockSession({ user: { id: 'user-a' } });
    const res = await GET(request('/api/projects/user-a-project-id'));
    expect(res.status).toBe(200);
  });
});
```
