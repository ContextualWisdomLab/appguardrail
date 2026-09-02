# ✅ Fixed Vibe App

**This is the secure version of the vulnerable example.**

See `../vulnerable-vibe-app/README.md` for the list of vulnerabilities that were fixed.

The fixed example also follows the ContextualWisdomLab naming contract: organization-owned database objects and internal identifiers use bounded-context-specific multiword names. Vendor-owned fields such as NextAuth `session.user.id` and Supabase `auth.users(id)` remain unchanged at their adapter boundaries.

---

## Security Fixes Applied

### 1. Ownership Check Added (IDOR Fixed)

`app/api/projects/[projectId]/route.ts`

```typescript
// ✅ SECURE: Authentication + ownership verification
import { auth } from '@/auth';
import { createClient } from '@/lib/supabase/server';

export async function GET(
  httpRequest: Request,
  { params }: { params: { projectId: string } }
) {
  // Step 1: Check authentication
  const authSession = await auth();
  if (!authSession) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const supabaseClient = createClient();

  // Step 2: Fetch the project
  const { data: projectRecord, error: projectQueryError } = await supabaseClient
    .from('project_records')
    .select('*')
    .eq('project_id', params.projectId)
    .single();

  // Step 3: Verify ownership. `authSession.user.id` is NextAuth-owned.
  if (
    projectQueryError ||
    !projectRecord ||
    projectRecord.owner_user_id !== authSession.user.id
  ) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

  return Response.json(projectRecord);
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
export const supabaseAdminClient = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY! // no NEXT_PUBLIC_ prefix!
);
```

`lib/supabase/client.ts` (browser)

```typescript
// ✅ SECURE: Client uses anon key only
import { createBrowserClient } from '@supabase/ssr';

export function createSupabaseBrowserClient() {
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

const stripeClient = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(httpRequest: Request) {
  const rawRequestBody = await httpRequest.text(); // raw body for signature verification
  const stripeSignature = httpRequest.headers.get('stripe-signature')!;

  let stripeEvent: Stripe.Event;
  try {
    stripeEvent = stripeClient.webhooks.constructEvent(
      rawRequestBody,
      stripeSignature,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
  } catch (signatureError) {
    console.error('Webhook signature verification failed:', signatureError);
    return Response.json({ error: 'Invalid signature' }, { status: 400 });
  }

  if (stripeEvent.type === 'checkout.session.completed') {
    const checkoutSession = stripeEvent.data.object as Stripe.Checkout.Session;
    await applicationDatabase.userAccount.update({
      where: { stripeCustomerId: checkoutSession.customer as string },
      data: { subscriptionPlan: 'pro' },
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

const stripeClient = new Stripe(process.env.STRIPE_SECRET_KEY!);

// Price IDs are defined server-side only
const PRICE_IDS = {
  pro_monthly: process.env.STRIPE_PRICE_ID_PRO_MONTHLY!,
  pro_annual: process.env.STRIPE_PRICE_ID_PRO_ANNUAL!,
} as const;

export async function POST(httpRequest: Request) {
  const authSession = await auth();
  if (!authSession) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { plan: selectedPlan } = await httpRequest.json();

  // Look up the price server-side — never from client
  const stripePriceId = PRICE_IDS[selectedPlan as keyof typeof PRICE_IDS];
  if (!stripePriceId) {
    return Response.json({ error: 'Invalid plan' }, { status: 400 });
  }

  const checkoutSession = await stripeClient.checkout.sessions.create({
    customer_email: authSession.user.email!,
    line_items: [{ price: stripePriceId, quantity: 1 }],
    mode: 'subscription',
    success_url: `${process.env.NEXT_PUBLIC_URL}/success`,
    cancel_url: `${process.env.NEXT_PUBLIC_URL}/pricing`,
  });

  return Response.json({ checkout_url: checkoutSession.url });
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
const applicationDatabase = new PrismaClient(); // uses DATABASE_URL from process.env automatically
```

---

### 6. Supabase RLS Enabled

`supabase/migrations/001_initial.sql`

```sql
-- ✅ SECURE: RLS enabled with proper policies and semantic owned names.
-- `auth.users(id)` is Supabase-owned and intentionally remains unchanged.
CREATE TABLE project_records (
  project_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id UUID REFERENCES auth.users(id) NOT NULL,
  project_name TEXT NOT NULL,
  project_payload JSONB
);

-- Enable Row Level Security
ALTER TABLE project_records ENABLE ROW LEVEL SECURITY;

-- Users can only see their own projects
CREATE POLICY "Users can view own project records"
  ON project_records FOR SELECT
  USING (auth.uid() = owner_user_id);

-- Users can only create projects owned by themselves
CREATE POLICY "Users can create own project records"
  ON project_records FOR INSERT
  WITH CHECK (auth.uid() = owner_user_id);

-- Users can only update their own projects
CREATE POLICY "Users can update own project records"
  ON project_records FOR UPDATE
  USING (auth.uid() = owner_user_id)
  WITH CHECK (auth.uid() = owner_user_id);

-- Users can only delete their own projects
CREATE POLICY "Users can delete own project records"
  ON project_records FOR DELETE
  USING (auth.uid() = owner_user_id);
```

The example is a fresh illustrative schema rather than a migration of an existing deployment. A real application that already has `projects(id, user_id, name, data)` must use an explicit forward migration and compatibility plan; renaming live PostgreSQL objects in place without tracing foreign keys, indexes, ORM mappings, RLS policies, UPSERT paths, locks, rollback, and deployed consumers is not safe.

---

### 7. Admin Auth Check Added

`app/api/admin/user-accounts/route.ts`

```typescript
// ✅ SECURE: Admin role verified server-side
import { auth } from '@/auth';

export async function GET(httpRequest: Request) {
  const authSession = await auth();

  // Step 1: Require authentication
  if (!authSession) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Step 2: Require admin role (from database, not just session claim)
  const userAccount = await applicationDatabase.userAccount.findUnique({
    where: { userAccountId: authSession.user.id },
    select: { accountRole: true },
  });

  if (userAccount?.accountRole !== 'admin') {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

  const userAccounts = await applicationDatabase.userAccount.findMany({
    select: {
      userAccountId: true,
      emailAddress: true,
      createdAt: true,
      subscriptionPlan: true,
    },
    // Never include passwords, secrets, or sensitive fields
  });

  return Response.json(userAccounts);
}
```

---

## Security Tests

Each fixed endpoint has corresponding tests:

```typescript
describe('GET /api/projects/[projectId]', () => {
  it('returns 401 when unauthenticated', async () => {
    const httpResponse = await GET(request('/api/projects/test-id'));
    expect(httpResponse.status).toBe(401);
  });

  it('returns 403 when accessing another user\\'s project', async () => {
    mockSession({ user: { id: 'user-a' } });
    const httpResponse = await GET(request('/api/projects/user-b-project-id'));
    expect(httpResponse.status).toBe(403);
  });

  it('returns 200 for the project owner', async () => {
    mockSession({ user: { id: 'user-a' } });
    const httpResponse = await GET(request('/api/projects/user-a-project-id'));
    expect(httpResponse.status).toBe(200);
  });
});
```
