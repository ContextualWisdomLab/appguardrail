# Handoff: AppGuardrail #309 / Naruon Scorecard CII-Best-Practices

Recorded: 2026-09-19 (KST)  
Workspace branch: `seonghobae/code-scanning-naruon-low-scorecard-ciibestpracti-2` @ `e71d37e7`  
Naruon develop head checked: `042b0c7`  
Orca: runtime ready; orchestration inbox empty (idle confirmed).

## Goal (unchanged)

Close [AppGuardrail #309](https://github.com/ContextualWisdomLab/appguardrail/issues/309) and Naruon code-scanning alert [#67](https://github.com/ContextualWisdomLab/naruon/security/code-scanning/67) by obtaining a verified `bestpractices.dev` project for `ContextualWisdomLab/naruon`, linking that URL from Naruon metadata, and confirming Scorecard `CII-Best-Practices` is no longer score `0` on `develop` — without fabricating OpenSSF attestations.

## Latest verification (authoritative)

| Signal | Result | Captured |
| --- | --- | --- |
| `https://www.bestpractices.dev/projects.json?url=https://github.com/ContextualWisdomLab/naruon` | **0 projects** | 2026-09-19 |
| Scorecard API `CII-Best-Practices` | **score 0** — `no effort to earn an OpenSSF best practices badge detected` (published Scorecard date `2026-06-30`) | 2026-09-19 |
| Naruon code-scanning alert #67 | **open** on `refs/heads/develop` @ `2ad9dcb766bf8864c5c6f9c4287152dcbb0420fe` | 2026-09-19 |
| Open Naruon code-scanning alerts | **only #67** (`CIIBestPracticesID`) | 2026-09-19 |
| AppGuardrail #309 | **OPEN** | 2026-09-19 |

### Change-control contract (do not weaken)

Active default-branch PR rules (additive; do not lower counts or disable):

| Ruleset | ID | `required_approving_review_count` | `require_last_push_approval` | `required_review_thread_resolution` |
| --- | --- | --- | --- | --- |
| PR | `15586698` | 0 | false | true |
| Lock default branch | `17214772` | **1** | **true** | true |
| CWL Central required workflows | `18156473` | **1** | false | true |

Effective contract for OpenSSF answers: describe the **integrated** repository + organization rulesets (not `15586698` alone). Collaborator inventory currently exposes only `seonghobae` (independent human review path tracked under Naruon #1371).

### Scorecard delivery path (already centralized)

Repo-local `.github/workflows/scorecard.yml` / `scorecard-analysis.yml` were intentionally removed from Naruon (`368a02a9`, “keep governance workflows deleted”). Organization required workflow `ContextualWisdomLab/.github` → `.github/workflows/security-scan.yml` already runs Scorecard as **soft** posture evidence (`category: scorecard`) and uploads SARIF. Restoring a duplicate repo-local Scorecard workflow is **out of scope** for this finding and risks reintroducing the duplicate-scan problem that #926 / centralization fixed.

## Classification

- Not an AppGuardrail product-code defect.
- Not closable by dismissing alert #67.
- Not closable by weakening branch protection / required approvals / required workflows.
- Root cause: **no OpenSSF Best Practices project registration** for the GitHub repository URL.

## Solvable in-repo (this handoff wave)

1. **AppGuardrail**: this handoff document + status comment on #309 (tracking evidence only).
2. **Naruon** (companion branch `governance/issue-1178-openssf-enrollment-prep`):
   - Correct `SECURITY.md` private-advisory URL from `Seongho-Bae/naruon` to `ContextualWisdomLab/naruon` (honest reporting channel for badge criteria).
   - Add `docs/governance/openssf-best-practices-enrollment.md` with evidence inventory, unmet criteria owners, and explicit **no fabricated attestation** rule.
   - Do **not** add a Best Practices badge markdown link until a live project id exists.

## External unlock conditions (required to finish the goal)

An authorized ContextualWisdomLab / Naruon representative must:

1. Sign in to [bestpractices.dev](https://www.bestpractices.dev/) (GitHub OAuth; agent sessions without an interactive signed-in browser cannot complete this).
2. Create or claim the project with repository URL exactly `https://github.com/ContextualWisdomLab/naruon`.
3. Answer criteria from current repository evidence only. Leave unmet criteria unmet with justification — **do not invent passing answers**.
4. Material gaps to disclose honestly at enrollment time:
   - License is **proprietary** (`NOASSERTION` / non-OSI). FLOSS `floss_license` style criteria will remain unmet unless license policy changes.
   - `GOVERNANCE.md` is absent.
   - Only one repository collaborator (`seonghobae`); effective review requires one independent post-last-push approval via rulesets `17214772` + `18156473`.
5. After a project id exists, open a Naruon PR that:
   - Links `https://www.bestpractices.dev/projects/<id>` from README (and/or the governance doc).
   - Does not weaken rulesets or required checks.
6. Wait for / trigger Scorecard refresh (central `security-scan` Scorecard job and/or published Scorecard API) until `CII-Best-Practices` is **not** score `0`.
7. Close AppGuardrail #309, Naruon #1178, and `.github` #694 only after alert #67 is resolved by refreshed evidence (not by dismissal).

### Agent OAuth blocker (recorded)

Playwright navigation to `https://www.bestpractices.dev/en/login` → “Log in with GitHub” lands on GitHub password/passkey login with **no existing session**. `gh` token scopes cannot create bestpractices.dev projects. Chrome remote-debugging for browser-use was off (`chrome://inspect/#remote-debugging`).

**Unlock for automation:** user completes GitHub OAuth in an agent-controllable browser (or creates the project manually and pastes the project id into the tracking issues).

## Explicit non-actions

- Do not dismiss code-scanning alert #67 to clear the dashboard.
- Do not lower `required_approving_review_count`, disable `require_last_push_approval`, or drop required central workflows.
- Do not re-add deleted repo-local Scorecard workflows as a substitute for badge enrollment.
- Do not claim a badge percentage or tier without a live `bestpractices.dev` project JSON record.

## Related trackers

- [appguardrail#309](https://github.com/ContextualWisdomLab/appguardrail/issues/309)
- [naruon#1178](https://github.com/ContextualWisdomLab/naruon/issues/1178)
- [ContextualWisdomLab/.github#694](https://github.com/ContextualWisdomLab/.github/issues/694)
- Prior code baseline: [naruon#854](https://github.com/ContextualWisdomLab/naruon/pull/854) (OpenSSF readiness sweep; subsequent centralization removed local Scorecard duplicates)

## Completion audit checklist (goal remains open until all true)

- [ ] `projects.json?url=.../naruon` returns ≥1 project with stable id
- [ ] Naruon metadata links that project URL on default branch
- [ ] Scorecard `CII-Best-Practices` score ≠ 0 (API and/or fresh code-scanning instance)
- [ ] Alert #67 closed by refresh (not dismissal)
- [ ] AppGuardrail #309 closed with evidence links
