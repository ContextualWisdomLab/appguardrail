### Documentation

- Updated the fixed Next.js/Supabase security example so organization-owned project schema and internal identifiers use bounded-context-specific multiword names (`project_records`, `project_id`, `owner_user_id`, `project_name`, `project_payload`) while vendor-owned NextAuth/Supabase identifiers remain at their adapter boundaries.
- Added regression coverage that prevents the fixed example from reintroducing the previous generic project table and column names.
