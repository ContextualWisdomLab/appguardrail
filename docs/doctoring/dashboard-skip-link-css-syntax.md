# Dashboard skip-link CSS syntax repair

## Buyer impact

The dashboard already places `Skip to content` as the first interactive control and targets the focusable `#app` main region, but protected `develop` encoded the CSS rule boundary as the two literal characters `\` and `n`. That is not a line break in a stylesheet. CSS tokenization therefore consumes the backslash sequence as escaped syntax instead of preserving the intended independent `.skip-link:focus` rule, so a sighted keyboard user cannot rely on the authored focus-reveal treatment when using the bypass link.

The repair changes only the two malformed rule boundaries to real line breaks. The skip-link text, DOM order, target, focus behavior, `--primary` token, white outline, spacing, and all other dashboard presentation remain unchanged.

## Test-first evidence

1. Regression commit `2246bb7085182c909968315e4ea0163efedf630f` adds `tests/test_dashboard_skip_link_css_contract.py`. The test rejects a literal `\n` between `.skip-link` and `.skip-link:focus` and requires a real newline rule boundary. It fails against the protected-base source.
2. Production commit `25e21889bdd250bca9f622cef4b319d47eb1d14c` replaces only the escaped boundaries in `scanner/dashboard/index.html` with actual newlines.
3. The pre-existing `test_dashboard_skip_link_is_first_and_targets_focusable_main` continues to own the DOM-order, target, and focus-style presence contract.

Hosted exact-head checks remain authoritative after publication. Queued, skipped-required, predecessor-head, author-only, model-only, or synthetic evidence is not merge evidence.

## Design-system boundary

`scanner/dashboard/tokens.json` remains the canonical dashboard token source. This repair introduces no token, component, state, layout, copy, or interaction decision, so it does not create a second design authority. A fresh repository search found no AppGuardrail Storybook implementation or recorded Figma design-file URL to update; inventing either for a two-character syntax defect would create rather than reconcile design authority. Any future visual redesign should establish Figma and Storybook together before changing this existing contract.

## Accessibility and standards rationale

WCAG 2.2 Success Criterion 2.4.1 requires a mechanism to bypass blocks repeated across pages. W3C Technique G1 specifically describes a link at the beginning of the page that moves focus to the main content. AppGuardrail already implements that semantic structure; this change restores the CSS necessary for its authored visible-on-focus presentation. CSS Syntax Level 3 defines backslash escape processing, which is why a literal `\n` sequence cannot substitute for a source newline between rules.

This bounded repair supports the existing bypass mechanism. It does not claim whole-product WCAG conformance, browser-wide accessibility certification, or a new visual design.

## Verification

For the unchanged candidate head:

- run `pytest -q tests/test_dashboard_skip_link_css_contract.py tests/test_dashboard_core.py`;
- run the repository's complete required test/security workflow set;
- verify the exact protected-base diff contains only the regression, syntax repair, this doctoring record, and the Unreleased changelog entry;
- verify all current review threads are resolved and a qualifying independent non-author approval exists before merge.

Manual browser verification, when available, is: press Tab from the document start, confirm `Skip to content` becomes visibly revealed, activate it, and confirm focus moves to the `#app` main region without changing dashboard data or filters.

## Rollback

Revert this bounded slice if it introduces a verified regression. Do not restore literal escaped rule boundaries; if focus presentation must change, replace it with a separately reviewed token-driven design contract.

## References

World Wide Web Consortium. (2026, February 9). *Understanding Success Criterion 2.4.1: Bypass Blocks*. https://www.w3.org/WAI/WCAG22/Understanding/bypass-blocks.html

World Wide Web Consortium. (2026). *Technique G1: Adding a link at the top of each page that goes directly to the main content area*. https://www.w3.org/WAI/WCAG22/Techniques/general/G1.html

World Wide Web Consortium. (2021). *CSS Syntax Module Level 3*. https://www.w3.org/TR/css-syntax-3/
