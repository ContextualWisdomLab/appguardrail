### Documentation

- Updated the fixed and intentionally vulnerable Next.js/Supabase security examples so organization-owned project schema and internal identifiers use bounded-context-specific multiword names (`project_records`, `project_id`, `owner_user_id`, `project_name`, `project_payload`) while vendor-owned NextAuth/Supabase/Zod identifiers remain at their adapter boundaries.
- Preserved the vulnerable fixture's intentional security failures while decoupling them from ambiguous organization-owned naming, so readers do not learn generic database names as part of the vulnerability demonstration.
- Added regression coverage that prevents either example from reintroducing the previous generic project table and column names, protects the fixed sample's existing API response/path contract, and keeps protected-request authentication/validation ordering explicit.
