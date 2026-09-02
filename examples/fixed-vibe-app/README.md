# ✅ Fixed Vibe App

**This is the secure version of the vulnerable example.**

See `../vulnerable-vibe-app/README.md` for the list of vulnerabilities that were fixed.

The fixed example also follows the ContextualWisdomLab naming contract: organization-owned database objects and internal identifiers use bounded-context-specific multiword names. Vendor-owned fields such as NextAuth `session.user.id`, Zod parse-result `data`, and Supabase `auth.users(id)` remain unchanged at their adapter boundaries.

---

## Security Fixes Applied

### 1. Ownership Check Added (IDOR Fixed)

`app/api/projects/[projectId]/route.ts`

```typescript
// ✅ SECURE: Authentication + validated project identifier + ownership verification
import { auth } from '@/auth';
import { createClient } from '@/lib/supabase/server';
import { z } from 'zod';

const projectIdSchema = z.string().uuid();

export async function GET(
  httpRequest: Request,
  { params }: { params: { projectId: string } }
) {
  // Step 1: Check authentication
  const authSession = await auth();
  if (!authSession) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Step 2: Validate route input before using it in a database predicate.
  const projectIdResult = projectIdSchema.safeParse(params.projectId);
  if (!projectIdResult.success) {
    return Response.json({ error: 'Invalid project identifier' }, { status: 400 });
  }
  const validatedProjectId = projectIdResult.data;

  const supabaseClient = createClient();

  // Step 3: Fetch the project
  const { data: projectRecord, error: projectQueryError } = await supabaseClient
    .from('project_records')
    .select('*')
    .eq('project_id', validatedProjectId)
    .single();

  // Step 4: Verify ownership. `authSession.user.id` is NextAuth-owned.
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

**Fix:** Authentication check + server-side UUID validation + ownership verification. Returns 403 (not 404) on ownership violation.

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
import { z } from 'zod';

const stripeClient = new Stripe(process.env.STRIPE_SECRET_KEY!);

// Public request key `plan` is preserved; the validated internal name is `selectedPlan`.
const checkoutRequestSchema = z
  .object({
    plan: z.enum(['pro_monthly', 'pro_annual']),
  })
  .strict();

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

  const checkoutRequestResult = checkoutRequestSchema.safeParse(
    await httpRequest.json().catch(() => null)
  );
  if (!checkoutRequestResult.success) {
    return Response.json({ error: 'Invalid checkout request' }, { status: 400 });
  }
  const selectedPlan = checkoutRequestResult.data.plan;

  // Look up the price server-side — never from client
  const stripePriceId = PRICE_IDS[selectedPlan];

  const checkoutSession = await stripeClient.checkout.sessions.create({
    customer_email: authSession.user.email!,
    line_items: [{ price: stripePriceId, quantity: 1 }],
    mode: 'subscription',
    success_url: `${process.env.NEXT_PUBLIC_URL}/success`,
    cancel_url: `${process.env.NEXT_PUBLIC_URL}/pricing`,
  });

  // Preserve the sample's established public response key.
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

`app/api/admin/users/route.ts`

```typescript
// ✅ SECURE: Admin role verified server-side and unsupported query input rejected
import { auth } from '@/auth';

export async function GET(httpRequest: Request) {
  // This listing accepts no query parameters; fail closed on unexpected input.
  const adminRequestUrl = new URL(httpRequest.url);
  if ([...adminRequestUrl.searchParams.keys()].length > 0) {
    return Response.json({ error: 'Unexpected query parameters' }, { status: 400 });
  }

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

Each fixed endpoint has corresponding tests. Route fixtures use UUID-shaped project identifiers so identifier validation and ownership behavior are tested independently:

```typescript
describe('GET /api/projects/[projectId]', () => {
  const ownerUserId = '11111111-1111-4111-8111-111111111111';
  const otherUserId = '22222222-2222-4222-8222-222222222222';
  const ownerProjectId = '33333333-3333-4333-8333-333333333333';
  const otherProjectId = '44444444-4444-4444-8444-444444444444';

  it('returns 401 when unauthenticated', async () => {
    const httpResponse = await GET(request(`/api/projects/${ownerProjectId}`));
    expect(httpResponse.status).toBe(401);
  });

  it('returns 400 for an invalid project identifier', async () => {
    mockSession({ user: { id: ownerUserId } });
    const httpResponse = await GET(request('/api/projects/not-a-uuid'));
    expect(httpResponse.status).toBe(400);
  });

  it('returns 403 when accessing another user\\'s project', async () => {
    mockSession({ user: { id: ownerUserId } });
    const httpResponse = await GET(request(`/api/projects/${otherProjectId}`));
    expect(httpResponse.status).toBe(403);
  });

  it('returns 200 for the project owner', async () => {
    mockSession({ user: { id: ownerUserId } });
    const httpResponse = await GET(request(`/api/projects/${ownerProjectId}`));
    expect(httpResponse.status).toBe(200);
  });
});
```
