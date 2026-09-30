### Fixed

- Preserve direct structured manifest arguments in Deno and CocoaPods registry
  write findings and capability inventory. `{"command":"deno","args":["publish"]}` and
  `{"command":"pod","args":["trunk","push"]}`, and bounded direct shell
  `-c` payloads—including JSON-escaped whitespace—now share the canonical
  Deno/CocoaPods classification for findings and inventory. Unsupported
  wrappers and different argument verbs remain outside these findings.
