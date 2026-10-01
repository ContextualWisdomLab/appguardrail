### Fixed

- Preserve direct structured manifest arguments in Deno and CocoaPods registry
  write findings and capability inventory. `{"command":"deno","args":["publish"]}` and
  `{"command":"pod","args":["trunk","push"]}`, and bounded direct shell
  `-c` payloads—including JSON-escaped whitespace—and bounded typed `env`
  wrappers now share the canonical Deno/CocoaPods classification for findings
  and inventory. `env` options that consume or split values, dynamic argv, and
  different argument verbs remain outside these findings.
- Require shell command-pattern matches to occupy a bounded executable position,
  so words passed to another program are not reported as registry writes while
  established path, `yarn npm`, and `python -m twine` forms remain supported.
- Treat POSIX bare `exec` and `command` as execution-preserving shell prefixes,
  so registry, deployment, and GitHub write commands cannot evade admission by
  replacing the hook shell process or bypassing shell functions. Typed process
  argv and option-bearing wrapper forms remain outside this bounded contract.
