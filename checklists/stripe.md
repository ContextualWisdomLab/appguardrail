# Stripe & Payments Security Checklist

Payment integrations are high-value targets. These are the most critical Stripe security issues in vibe-coded apps.

---

## Webhook Security

- [ ] Every Stripe webhook handler verifies the signature before processing:
  ```typescript
  const sig = req.headers['stripe-signature'];
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET!);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  ```
- [ ] The raw request body is used for signature verification (not the parsed JSON body).
- [ ] `STRIPE_WEBHOOK_SECRET` is different for local development (Stripe CLI) and production (Stripe Dashboard).
- [ ] The webhook endpoint returns `200` quickly and processes events asynchronously if needed.
- [ ] Idempotency is handled: duplicate events do not create duplicate charges or fulfillments.
- [ ] Webhook events are checked by type before processing (`event.type === 'payment_intent.succeeded'`).

## Price & Amount Integrity

- [ ] Prices are **never** passed from the client to the server.
- [ ] Price IDs are always retrieved server-side from Stripe or from your own database.
- [ ] Checkout sessions are created server-side with a `price` from `process.env` or your DB — not from `req.body.price`.
  ```typescript
  // ✅ Correct
  const session = await stripe.checkout.sessions.create({
    line_items: [{ price: process.env.STRIPE_PRICE_ID_PRO, quantity: 1 }],
    ...
  });

  // ❌ Wrong
  const session = await stripe.checkout.sessions.create({
    line_items: [{ price: req.body.priceId, quantity: 1 }], // attacker controls price!
    ...
  });
  ```
- [ ] Amounts in custom payment intents are calculated server-side, not passed from the client.

## Checkout & Customer Management

- [ ] Checkout sessions are authenticated — the customer ID or user ID is attached server-side.
- [ ] The billing portal endpoint verifies the authenticated user owns the Stripe customer ID being managed.
  ```typescript
  // Verify the user owns this Stripe customer before creating portal session
  const user = await db.user.findUnique({ where: { id: session.user.id } });
  if (user.stripeCustomerId !== customerId) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  ```
- [ ] Stripe customer IDs are stored server-side and looked up by the authenticated user's database ID.

## Secret Key Management

- [ ] `STRIPE_SECRET_KEY` is a server-side environment variable only.
- [ ] `STRIPE_SECRET_KEY` does not use `NEXT_PUBLIC_` prefix.
- [ ] The publishable key (`NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY`) is the only Stripe key in client code.
- [ ] Production and test keys are not mixed (`sk_live_` vs `sk_test_`).

## Subscription Management

- [ ] Subscription status is verified server-side before granting access to paid features.
- [ ] Subscription status comes from the database (updated via webhooks) or from Stripe directly — not from client claims.
- [ ] Cancellation, upgrade, and downgrade flows are tested for authorization (user can only modify their own subscription).

## Common Stripe Mistakes in AI-Generated Code

| Mistake | Fix |
|---|---|
| No webhook signature verification | Add `stripe.webhooks.constructEvent` |
| Price ID or amount from `req.body` | Look up price server-side |
| `STRIPE_SECRET_KEY` as `NEXT_PUBLIC_*` | Remove `NEXT_PUBLIC_` prefix; server-only |
| Billing portal without ownership check | Verify `stripeCustomerId` matches authenticated user |
| `checkout.sessions.create` without auth | Attach `client_reference_id` or `customer` from session |
| Fulfillment logic in the API route response (not webhook) | Move fulfillment to `payment_intent.succeeded` webhook |
