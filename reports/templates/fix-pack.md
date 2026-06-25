# AppGuardrail Fix Pack

A Fix Pack is the actionable output from an AppGuardrail review. Each entry contains a specific vulnerability, its risk, an AI-ready fix prompt, and a verification step.

**App:** [App Name]
**Fix Pack generated:** [Date]
**Based on review:** [Review ID or link]

---

## How to Use This Fix Pack

1. Work through each item from top to bottom (Critical → High → Medium).
2. For each item, copy the **Fix Prompt** and paste it into Claude Code, Cursor, or your preferred AI coding assistant.
3. After the AI applies the fix, run the **Verification Test** to confirm it works.
4. Check the item off once verified.

---

## Fix Items

### [ ] FIX-01: [Short Title]

**Severity:** 🔴 Critical

**Problem:**
[Plain-language description of the vulnerability. Example:
"User A can read User B's project data by changing the project ID in the API request.
There is no server-side check that the authenticated user owns the requested project."]

**Risk:**
[What could happen if this is not fixed. Example:
"Any authenticated user can access any other user's projects, tasks, and files.
This is a complete data confidentiality breach."]

**Fix Prompt:**
```
Update the GET /api/projects/[id] route to verify that the authenticated user owns the
requested project before returning data.

After fetching the project, add:
  if (!project || project.ownerId !== session.user.id) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

Apply the same check to PUT and DELETE /api/projects/[id].

Also add tests:
  - Unauthenticated request → 401
  - Authenticated user accessing another user's project → 403
  - Authenticated user accessing their own project → 200
```

**Verification:**
1. Log in as User A.
2. Note the ID of one of User A's projects.
3. Log in as User B.
4. Make a GET request to `/api/projects/[User A's project ID]`.
5. Expected result: HTTP 403 Forbidden.
6. Confirm User B cannot see User A's project data.

---

### [ ] FIX-02: [Short Title]

**Severity:** 🔴 Critical

**Problem:**
[Description]

**Risk:**
[Risk]

**Fix Prompt:**
```
[Fix prompt]
```

**Verification:**
[Verification steps]

---

### [ ] FIX-03: [Short Title]

**Severity:** 🟠 High

**Problem:**
[Description]

**Risk:**
[Risk]

**Fix Prompt:**
```
[Fix prompt]
```

**Verification:**
[Verification steps]

---

## Fix Pack Status

| ID | Title | Severity | Status | Fixed By | Verified |
|---|---|---|---|---|---|
| FIX-01 | [Title] | Critical | ⏳ Open | | |
| FIX-02 | [Title] | Critical | ⏳ Open | | |
| FIX-03 | [Title] | High | ⏳ Open | | |

---

## Post-Fix Checklist

After all fixes are applied:

- [ ] Run `appguardrail scan .` — confirm no new issues introduced
- [ ] Run existing test suite — confirm no regressions
- [ ] Deploy to staging and repeat the verification tests
- [ ] Get sign-off from reviewer before deploying to production

---

## Questions?

If a fix prompt doesn't produce the right result, or if you need clarification on any item, contact AppGuardrail for follow-up support.
