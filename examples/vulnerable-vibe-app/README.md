# ⚠️ WARNING: Intentionally Vulnerable Application

**This is a demonstration of insecure code patterns for educational purposes.**
**DO NOT deploy this to a public URL. DO NOT use real credentials.**

This example shows common security mistakes in AI-generated Next.js + Supabase apps. The security flaws are intentional; ambiguous ContextualWisdomLab-owned names are not. Organization-owned identifiers use bounded-context-specific names while vendor-owned fields such as Supabase `auth.users(id)` and response `data`/`error` remain at their adapter boundaries.
See `../fixed-vibe-app/` for the corrected security version.

---

## Vulnerabilities Demonstrated

### 1. Missing Ownership Check (IDOR)

`app/api/projects/[projectId]/route.ts`

```typescript
// ❌ VULNERABLE: No ownership check — any user can access any project
export async function GET(
  httpRequest: Request,
  { params }: { params: { projectId: string } }
) {
  const supabaseClient = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  );

  // No authentication check!
  // No ownership verification!
  const { data: projectRecord, error: projectQueryError } = await supabaseClient
    .from('project_records')
    .select('*')
    .eq('project_id', params.projectId)
    .single();

  // The ignored error and missing authorization are intentionally vulnerable.
  void projectQueryError;
  return Response.json(projectRecord);
}
```

**Impact:** Any user (authenticated or not) can read any project by guessing or iterating project IDs.

---

### 2. Service Role Key Exposed Client-Side

`lib/supabase.ts`

```typescript
// ❌ VULNERABLE: Service role key used in a file that can be imported by client components
import { createClient } from '@supabase/supabase-js';

export const supabaseAdminClient = createClient(
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
export async function POST(httpRequest: Request) {
  const unverifiedStripeEvent = await httpRequest.json(); // trusting the body directly!

  if (unverifiedStripeEvent.type === 'checkout.session.completed') {
    // Attacker can POST a fake 'checkout.session.completed' event
    // and get any account upgraded to Pro for free
    await applicationDatabase.userAccount.update({
      where: { stripeCustomerId: unverifiedStripeEvent.data.object.customer },
      data: { subscriptionPlan: 'pro' },
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
export async function POST(httpRequest: Request) {
  const { priceId: clientPriceId } = await httpRequest.json(); // attacker controls this!

  const checkoutSession = await stripe.checkout.sessions.create({
    line_items: [{ price: clientPriceId, quantity: 1 }], // price from attacker!
    mode: 'subscription',
    success_url: `${process.env.NEXT_PUBLIC_URL}/success`,
    cancel_url: `${process.env.NEXT_PUBLIC_URL}/pricing`,
  });

  return Response.json({ url: checkoutSession.url });
}
```

**Impact:** An attacker can supply a price ID for a cheaper plan (or a free trial) and bypass payment.

---

### 5. Hardcoded Secret

`lib/db.ts`

```typescript
// ❌ VULNERABLE: Hardcoded database URL
const applicationDatabase = new PrismaClient({
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
-- `auth.users(id)` is Supabase-owned and intentionally remains unchanged.
CREATE TABLE project_records (
  project_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id UUID REFERENCES auth.users(id),
  project_name TEXT,
  project_payload JSONB
);

-- Missing: ALTER TABLE project_records ENABLE ROW LEVEL SECURITY;
-- Missing: CREATE POLICY ... USING (auth.uid() = owner_user_id);
```

**Impact:** Any authenticated user can read, modify, or delete any row in the `project_records` table via the Supabase client.

---

### 7. TODO Auth Bypass

`app/api/admin/users/route.ts`

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

All of these vulnerabilities are fixed in `../fixed-vibe-app/`. Compare the two to understand each security fix without conflating insecure behavior with ambiguous organization-owned naming.
