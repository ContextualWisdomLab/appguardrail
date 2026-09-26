# Python shell-call detection is syntax-aware

- Detect actual `os.system(...)` calls and `subprocess` calls whose `shell`
  keyword is not statically false.
- Ignore comments, string literals, assignments, `shell=False`, `shell=0`,
  and `shell=None` so non-executable text does not create CRITICAL findings.
- Preserve the legacy regex only as a fail-closed fallback for syntax-invalid
  Python and retain exact source offsets, including non-ASCII source lines.
