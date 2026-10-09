### Security

- Normalize imported findings through one fail-closed serialization boundary:
  suppress complete snippets for secret-category and genuinely sensitive-rule
  findings, recursively redact raw/credential-named extension fields, and
  selectively redact obvious authorization, credential-assignment,
  provider-token, and JWT material from all other text before reports, SARIF,
  or control-plane persistence.
- Sanitize secret-bearing mapping keys, post-coercion text, plural/camel-case
  sensitive fields, arbitrary Authorization schemes, and AWS access-key
  identifiers while bounding snippet inspection before pattern matching.
- Consume multiline quoted credentials, cover scoped `sk-proj-*` and
  `sk-svcacct-*` tokens, validate report line numbers without deferred string
  coercion, and inspect bounded lookahead so truncation cannot expose a token
  prefix at the report boundary.
- Cover suffixed compound credential fields and triple-quoted/backtick values;
  lookahead now marks source-aligned secret spans without moving text from
  beyond the configured snippet boundary into serialized output.
- Treat escaped characters inside triple-quoted credentials as content rather
  than a closing delimiter, preventing the remaining secret body from leaking.
- Preserve non-sensitive evidence and existing truncation behavior. Unknown
  secret formats outside raw/credential-named fields depend on a
  format-specific redaction pattern; regression fixtures use only synthetic
  values. Provider-related non-secret rules do not suppress benign evidence.
