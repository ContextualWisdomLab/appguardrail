# Product–Technical Gap Baseline

Status: **Proposed**  
Last evidence refresh: 2026-09-20  
Current review: [appguardrail#1272](https://github.com/ContextualWisdomLab/appguardrail/pull/1272)  
Additional measured-performance lane: [appguardrail#1247](https://github.com/ContextualWisdomLab/appguardrail/pull/1247) at `b857142c068d65c77393f424340684d9c634e546`  
Production evidence ancestor: `f76fcbabc867b0953b260908116a162314619f63`

## Goal and loop

AppGuardrail must present scanner findings without changing finding truth or surprising users with an unannounced browsing-context change. Review the exact PR head, preserve the reference-link contract with executable tests, run exact-head checks, obtain real-browser and independent evidence, then merge ordinarily. Pending evidence keeps the change Draft/Proposed.

## PRD

A finding reference must preserve the source URL as visible text, admit only the dashboard's existing safe URL boundary, announce that activation opens a new tab, and expose the icon as decorative. Pointer, touch, keyboard, and assistive-technology users must receive equivalent meaning. Presentation state never replaces the finding record.

## TRD

`scanner/dashboard/index.html` remains the product-owned, dependency-free static dashboard. External references use the reusable `external-reference` class, `target="_blank"`, `rel="noopener noreferrer"`, one English context-change string consistent with the document's current `lang="en"`, and an `aria-hidden`/non-focusable SVG. `tests/test_dashboard_external_reference_contract.py` fixes this source contract. The removed root `test_playwright.py` contained no assertions, used a fixed `/app` path, and was not an executable acceptance gate.

Figma component ID: **none evidenced**. Storybook story: **none evidenced**.

## Context Map

```mermaid
flowchart LR
  Report[Finding Report Truth] -->|read-only finding DTO| Dashboard[AppGuardrail Dashboard]
  Dashboard -->|safe reference link| Browser[Browser Context]
  Dashboard -->|name and context-change text| AT[Assistive Technology]
  Browser -->|HTTP or HTTPS navigation| Authority[External Reference Authority]
```

- Finding Report Context owns rule, evidence, remediation, and reference values.
- Dashboard Presentation Context owns escaping, safe-link admission, visible disclosure, focus, and interaction.
- External content never becomes AppGuardrail domain truth.

## UML

```mermaid
sequenceDiagram
  participant U as User
  participant D as Dashboard
  participant B as Browser
  participant A as External Authority
  U->>D: Open finding details
  D-->>U: Visible URL + new-tab disclosure
  U->>D: Activate reference
  D->>B: Safe HTTP(S) navigation with opener isolation
  B->>A: Request reference
```

## ERD

No database entity or relationship is introduced by #1272. The dashboard consumes an immutable finding-report snapshot; link presentation is derived and must not be persisted as finding truth.

## Exact-head acceptance matrix

| Concern | Current evidence | Status |
|---|---|---|
| Determinism | Source contract fixes class, relationship, disclosure, and decorative SVG semantics | Source PASS; hosted checks pending |
| Semantics | Visible source URL remains distinct from hidden context-change text | PASS |
| Accessibility | Hidden context notice and decorative icon boundary are source-tested | PARTIAL; real AT absent |
| Pointer/touch/keyboard | Native anchor behavior exists; browser pointer, touch, Tab, Enter and context-change replay absent | FAIL |
| Responsive | Inline layout moved to reusable CSS; 320/768/desktop screenshots absent | FAIL |
| Locales | Current document is English; ko/en/ja/zh/vi/es/de/fr resource authority and wrapping evidence absent | FAIL |
| States | Finding detail and reference-present state exist; offline, permission, stale, retry, busy and broken-reference evidence absent | FAIL |
| Large data | Reference-list render and interaction median/p95 absent | FAIL |
| Import/export | Finding report remains input truth; no presentation DTO is exported | PARTIAL |
| Recovery | Close/focus restoration exists; popup-blocked, offline and reload recovery evidence absent | FAIL |

## Gap and action ledger

| Gap | Required action | Status |
|---|---|---|
| Unstable inline presentation | Use the product-owned `external-reference` class | Repaired; checks pending |
| Weak opener isolation declaration | Require `noopener noreferrer` | Repaired; checks pending |
| Decorative SVG focus ambiguity | Require `aria-hidden="true" focusable="false"` | Repaired; checks pending |
| False browser evidence | Remove the assertion-free, fixed-path smoke artifact | Repaired |
| Browser and AT acceptance | Exercise pointer, touch, Tab/Enter, accessible name, focus return and popup-blocked recovery in current Chromium/Firefox/WebKit | Open |
| Responsive evidence | Capture 320 px, 768 px and desktop reference wrapping/overflow screenshots | Open |
| Locale authority | Provide released ko/en/ja/zh/vi/es/de/fr screen resources or a bounded language decision | Open |
| Severity-cache performance claim | Preserve exact/fresh-set semantics; record benchmark command, environment, warm-up, sample size, failure denominator, median/p95, and real calling-path impact before claiming a percentage | Source/test repaired in #1247; measurement open |
| Performance and recovery | Measure realistic reference-list median/p95 and verify offline/reload behavior | Open |

## Release decision

Keep appguardrail#1272 **Draft/Proposed** until exact-head CI and security checks are terminal GREEN, actionable review threads are resolved, current-head independent approval exists, and applicable browser, accessibility, responsive, locale, performance, and recovery rows pass. No release or GitHub Pages publication is claimed.


## Native findings-file input acceptance — appguardrail#1329

Product source remains single-writer appguardrail#1329. Exact recovery head: `66a5e0e142d8cb5521bc9e2282bb7e5a1f73bae4`.

### PRD / TRD / Context Map

An analyst must open a findings JSON file through the operating-system picker with native keyboard, pointer, touch and assistive-technology semantics. The product keeps the native `input[type=file]` as the interaction owner, associates a styled label, forwards `:focus-visible` to the label, and does not introduce a JavaScript click proxy. Imported JSON remains scanner domain input; the presentation layer does not replace finding truth.

```mermaid
flowchart LR
  Analyst -->|activate label/input| NativePicker[Native File Picker]
  NativePicker -->|selected file| Dashboard[Scanner Dashboard]
  Dashboard -->|parse| Findings[Finding Report]
```

No database entity or relationship changes.

### Exact-head acceptance matrix

| Concern | Evidence | Status |
|---|---|---|
| Native semantics | Focusable input, associated label, no `aria-hidden`/`tabindex=-1` | Source PASS |
| Keyboard/focus | Focus indicator forwarded to styled label | Source PASS; browser/AT pending |
| Determinism | Regression contract rejects JS click proxy and literal `\\n` CSS | Source PASS |
| Pointer/touch | Native activation expected | Chromium/Firefox/WebKit and touch evidence missing |
| Responsive/locales | Header wrapping at 320/768/desktop and 8 locales | FAIL |
| Import/error/recovery | valid/invalid/large file, cancel, retry, reload, offline | FAIL |
| Performance | realistic large report parse/render median and p95 | FAIL |
| Hosted validation | exact-head CI/security and independent approval | Pending |

Repeated successor regression at `280a278e…` removed the contracts and restored the inaccessible proxy. Ordinary-forward recovery restored tests `b1923ce3…`/`df548fba…`, product `9cc0068b…`, guidance `1f40de72…`, and CHANGELOG `66a5e0e1…`. Keep Draft until the remaining matrix is GREEN.


## Duplicate external-reference writer — appguardrail#1332

[appguardrail#1332](https://github.com/ContextualWisdomLab/appguardrail/pull/1332) is Draft/Proposed at exact head `e1d46111bb1c46e4495c5d96e8c976d48a0532fc`. The same dashboard external-reference surface is already owned by canonical appguardrail#1272 at `db690d5f6a87318795ac813d269e3c72a9f8b7ac`, which preserves the reusable `.external-reference` class, `noopener noreferrer`, non-focusable `aria-hidden` SVG, visible new-context text, focused regression contract, CHANGELOG, and this Gap ledger.

#1332 is not a complete successor: it uses only `rel="noopener"`, exposes the SVG to assistive technology, lacks a focused contract, and applies `word-break: break-all` to every anchor rather than the bounded external-reference component. Preserve its proposal and Korean-copy intent, but do not create a second product writer or close it until protected integration proves complete blob/requirement carryover. Exact-head Tests, Security, Semgrep and CodeQL are queued; real browser/AT/responsive/eight-locale/recovery evidence and current independent approval remain absent.
