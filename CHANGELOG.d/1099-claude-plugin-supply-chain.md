### Security

- Scan Claude plugin marketplace/package manifests as hostile supply-chain
  artifacts: floating Git refs, provider API keys, `curl|sh` installers,
  undeclared hook/script surfaces, symlink escapes, duplicate JSON members,
  unbounded MCP servers, missing LICENSE/NOTICE evidence, concealed bidi/control
  identity, aggregate-byte-budget overruns, source-path symlink escapes, and
  marketplace/artifact source mismatch. Unreadable regular files retain an
  explicit fail-closed state instead of masquerading as empty payloads, and
  all supported shell, JavaScript, TypeScript, and Python hook suffixes receive
  the same content inspection. A deterministic scan receipt binds policy and
  artifact digests without echoing secrets; `pass` means
  the exact tree satisfied the exact AppGuardrail policy, not activation.
  `.claude-plugin/` is included in the scan walk.
