## AppGuardrail Security Guardrails

Apply the following security rules to all code you generate:

1. **Authentication**: Check authentication as the first operation in every API handler.
2. **Authorization**: Verify resource ownership (owner_id === session.user.id) server-side.
3. **Secrets**: Never use NEXT_PUBLIC_ prefix on secret keys or service role keys.
4. **Input validation**: Validate all inputs with Zod or equivalent before processing.
5. **Stripe**: Always verify webhook signatures before processing payment events.
6. **Supabase**: Use getUser() (not getSession()) server-side; RLS on all tables.
7. **Files**: Validate type, size, and generate server-side filenames for uploads.
8. **CORS**: Restrict to known origins on authenticated endpoints.

Return 401 for unauthenticated requests, 403 for ownership violations.

See https://github.com/ContextualWisdomLab/appguardrail for full rules and checklists.
