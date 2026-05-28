# Stripe Webhook Security Review Prompt

Use this prompt to audit and fix Stripe webhook handling in your project.

---

## Stripe Webhook Audit Prompt

```
Please review and fix the Stripe webhook implementation in this project to ensure
it is secure against replay attacks, unauthorized requests, and business logic manipulation.

## Step 1: Verify Webhook Signature Verification

Find every Stripe webhook handler in this codebase (usually in /api/webhooks/stripe
or similar). For each handler, ensure it verifies the Stripe signature:

```typescript
// The raw body MUST be used — not the parsed JSON
const rawBody = await req.text(); // or req.body as Buffer
const sig = req.headers.get('stripe-signature') ?? req.headers['stripe-signature'];

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
```

If the handler is missing signature verification, add it.
If the handler uses the parsed body (req.body as object) instead of raw bytes, fix it.

## Step 2: Verify Price Integrity

Search the codebase for Stripe checkout session creation. Ensure prices are
never taken from the request body:

```typescript
// ✅ Correct: price comes from environment or server-side lookup
const session = await stripe.checkout.sessions.create({
  line_items: [{
    price: process.env.STRIPE_PRICE_ID_PRO!, // from env, not req.body
    quantity: 1,
  }],
  ...
});

// ❌ Fix this pattern: price from client
const session = await stripe.checkout.sessions.create({
  line_items: [{ price: req.body.priceId, quantity: 1 }], // INSECURE
  ...
});
```

## Step 3: Verify Idempotency

Ensure the webhook handler does not process the same event twice:
- Check if there is a mechanism to deduplicate events by event.id
- If not, add one (store processed event IDs in the database)

## Step 4: Verify Event Type Checking

Ensure the handler explicitly checks event.type before taking action:
```typescript
switch (event.type) {
  case 'checkout.session.completed':
    await handleCheckoutCompleted(event.data.object as Stripe.Checkout.Session);
    break;
  case 'customer.subscription.deleted':
    await handleSubscriptionDeleted(event.data.object as Stripe.Subscription);
    break;
  default:
    // Unhandled event type — log and ignore safely
    console.log(`Unhandled event type: ${event.type}`);
}
```

## Step 5: Verify Billing Portal Authorization

Find the billing portal endpoint. Ensure it:
1. Requires authentication
2. Verifies the user owns the Stripe customer ID being accessed

```typescript
const user = await db.user.findUnique({ where: { id: session.user.id } });
if (!user?.stripeCustomerId) {
  return Response.json({ error: 'No billing account found' }, { status: 404 });
}
// Create portal session using the authenticated user's customer ID only
const portalSession = await stripe.billingPortal.sessions.create({
  customer: user.stripeCustomerId, // from DB, not from request
  return_url: `${process.env.NEXT_PUBLIC_URL}/dashboard`,
});
```

List all changes made and any issues that could not be automatically fixed.
```
