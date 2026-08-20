### Security

- Encode every untrusted organization-console value before dynamic HTML
  insertion, including scan summaries, trend labels, opaque identifiers,
  history totals, pill values, and finding details. A rendered Chrome
  regression now proves hostile script and image-event payloads remain inert
  without adding a browser package to AppGuardrail runtime dependencies.
