# Product technical gap baseline

Status: Proposed  
Last evaluated source commit: `344f1e9120094f3d3c7648c774716455fce7aeb5`  
Pull request: [#1342](https://github.com/ContextualWisdomLab/appguardrail/pull/1342)

## Product and boundary

appguardrail owns scanner findings and dashboard presentation. The file input remains an implementation detail behind the product-owned Upload findings button. This change corrects the documented accessibility contract; it does not move scanner or security-domain truth into presentation state.

| Artifact | Current evidence | Status |
| --- | --- | --- |
| PRD / TRD | docs/PRD.md and docs/TRD.md | Existing |
| UML / ERD | docs/UML.md and docs/ERD.md | Existing; no model change |
| Context Map | appguardrail remains scanner and dashboard owner; no Core dependency added | Preserved |
| Gap | Guidance incorrectly claimed `aria-hidden="true"` retained file-input AOM exposure | Repaired, verification pending |
| Action | Keep #1342 Draft until exact-head checks, current-head review, real-browser upload lifecycle evidence, and required locale evidence are complete | Open |

## Exact-head acceptance matrix

| Dimension | Evidence | Status |
| --- | --- | --- |
| Determinism | File proxy wiring remains `button#header-browse` → `input#file.click()` | Source contract GREEN |
| Semantics | Guidance now states that `aria-hidden` removes the input from the accessibility tree | Local contract GREEN |
| Accessibility | Test binds the documented AOM claim to the actual proxy implementation | Exact-head CI queued |
| Interaction | Pointer and native button keyboard activation use the same click handler | Source evidence only |
| Lifecycle / recovery | Cancel, same-file reselection, parse error, busy state, and focus restoration lack repaired-head browser evidence | FAIL |
| Responsive evidence | No desktop, intermediate, or mobile screenshots on the repaired head | FAIL |
| Locales | ko/en/ja/zh/vi/es/de/fr evidence is absent | FAIL |
| Large-data performance | No findings rendering or scanner algorithm changed | Not affected |
| Import/export | Native JSON import path changed in the PR; end-to-end recovery evidence is incomplete | FAIL |

An applicable FAIL is not merge-ready. The PR remains Draft until the missing evidence is attached to an unchanged successor head.
