# Console DOM XSS output-encoding boundary

**Status:** Active successor to PR #992; not protected-`develop` truth until integration.

## Buyer-visible security outcome

The organization console treats every scan-list and scan-detail value returned by
the control plane as untrusted data. Values interpolated into HTML strings are
encoded at the final sink before assignment to `innerHTML`, including labels,
counts, opaque identifiers, repository and commit text, trend labels, finding
metadata, locations, and error messages. Values used only through `textContent`
remain on that safer sink.

The numeric pill helper also encodes the displayed value. Its color remains a
fixed caller-owned design token rather than API data. Trend heights are derived
through numeric arithmetic and colors are selected from a fixed local map.

## Executable evidence

- `tests/test_console_xss_contract.py` binds every supported dynamic HTML
  interpolation to `esc(...)` and rejects the predecessor raw forms.
- `tests/test_console_xss_browser.py` serves the shipped page and hostile JSON
  from one bounded loopback origin, injects both script and image-event payloads
  across list and detail fields, drives list and detail rendering, and asserts
  that no attacker node or execution marker appears in the final DOM.
- `.github/workflows/console-xss-browser.yml` provisions Chrome through the
  immutable `browser-actions/setup-chrome` commit
  `48ad923757ca74d66703209fe939badbdf80f2f4`, records the browser version, and
  runs the rendered regression without adding Playwright or another browser
  package to AppGuardrail runtime dependencies.
- The complete repository suite and security/SAST gates remain required on the
  same exact head.

## Limits and next action

`innerHTML` remains in the no-build console for structured table rendering.
Therefore every new interpolation must either use the local context-appropriate
encoder or move to a safer DOM API such as `textContent`. This change does not
claim whole-product XSS elimination, CSP/Trusted Types deployment, or browser
console certification. A later refactor may replace string-built rows with DOM
node construction, but it must preserve the current keyboard, focus, and
no-build contracts.

## Rollback

Do not revert only the encoder calls. A rollback must remove the affected
feature or restore an equally strong sink-specific encoding and rendered-browser
regression. Any newly introduced raw interpolation is a release blocker.

## References

MITRE. (2026). *CWE-79: Improper neutralization of input during web page
generation ('Cross-site Scripting')*. Common Weakness Enumeration.
https://cwe.mitre.org/data/definitions/79.html

OWASP Foundation. (n.d.). *DOM based XSS prevention cheat sheet*. OWASP Cheat
Sheet Series. Retrieved August 20, 2026, from
https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
