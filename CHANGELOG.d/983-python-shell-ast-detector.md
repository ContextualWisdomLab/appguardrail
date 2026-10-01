### Security

- Replace regex-only Python shell-call matching with an AST-backed detector that
  resolves `os` and `subprocess` aliases, handles arbitrary parsed argument
  nesting, ignores comments and strings, respects lexical shadowing, and keeps
  malformed work-in-progress files non-crashing. `subprocess` findings remain
  limited to literal `shell=True`, while `subprocess.getoutput` and
  `subprocess.getstatusoutput` are implicit shell APIs. Existing rule identity
  and remediation copy are preserved.
- Restore module-import resolution after Python deletes an exception alias or
  explicit binding in a class body, while keeping function-local and module
  deletions shadowed so the precision boundary remains fail closed.
