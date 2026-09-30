### Fixed

- Preserve direct structured manifest arguments in Deno and CocoaPods registry
  write findings and capability inventory. `{"command":"deno","args":["publish"]}` and
  `{"command":"pod","args":["trunk","push"]}`, and bounded direct shell
  `-c` payloads now fail admission under the existing rule identities;
  unsupported wrappers and different argument verbs remain outside these
  findings.
