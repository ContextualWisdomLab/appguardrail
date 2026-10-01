### Security

- Added bounded JavaScript/TypeScript SAST rules for the ScopeWeave password-boundary weakness fixed in PR `#386`: coercive `String(password).length` validation before hashing and `password || ''` forwarding before password verification now map to `CWE-1287` when they originate from the observed untyped JSON request shape.
- Pinned vulnerable/fixed ScopeWeave revisions and affected `server/app.mjs` / `server/auth.mjs` blobs, with AppGuardrail issues `#770` and `#772` retained as workflow-event provenance rather than vulnerability proof.
