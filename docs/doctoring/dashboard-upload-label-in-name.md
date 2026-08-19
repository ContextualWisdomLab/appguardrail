# Dashboard upload label-in-name evidence

**Status:** Active PR #969; not protected-`develop` truth until integration.

## Decision

The findings-file upload proxy uses a native `button` whose visible text is exactly `Upload findings file`. That same text supplies the accessible name; the control does not override it with a divergent `aria-label`.

This keeps the visible action and the name exposed to assistive technology aligned while preserving the existing native keyboard activation, tokenized `.upload-action` presentation, hidden programmatic file input, drag-and-drop path, cancellation behavior, and same-file reselection behavior.

## Executable evidence

`tests/test_dashboard_file_upload_contract.py` requires the exact native button markup, rejects an `aria-label` override on the proxy, preserves the hidden-input contract, and keeps the same-file reset boundary executable.

The current branch deliberately makes no whole-product WCAG conformance, browser/screen-reader interoperability, or certification claim. Exact-head repository and organization checks plus independent review remain required before protected integration.

## Standards basis

WCAG 2.2 Success Criterion 2.5.3 requires that, for controls whose labels contain text or text images, the accessible name contain the text presented visually. The W3C understanding document further recommends matching the visible label and, where practical, beginning the accessible name with the same words.

World Wide Web Consortium Web Accessibility Initiative. (2026, April 5). *Understanding Success Criterion 2.5.3: Label in Name*. https://www.w3.org/WAI/WCAG22/Understanding/label-in-name

World Wide Web Consortium Web Accessibility Initiative. (2025, September 8). *G211: Matching the accessible name to the visible label*. https://www.w3.org/WAI/WCAG22/Techniques/general/G211

## Rollback

Rollback the label/name alignment, its focused regression, and this doctoring record together. Do not restore a visible `Upload file` label paired with a different `Upload findings file` accessible name.