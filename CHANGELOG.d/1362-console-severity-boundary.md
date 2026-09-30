## Fixed

- Restricted control-plane console severity colors to the static own-property
  allowlist. Inherited keys such as `constructor` now use the INFO color while
  their displayed labels remain HTML-escaped. An executable Node DOM regression
  covers the rendered result; this is defensive UI-integrity hardening, not a
  demonstrated XSS or prototype-pollution exploit.
