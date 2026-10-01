### Changed

- SARIF rendering now records each rule's insertion index once instead of
  repeatedly scanning prior rules, while preserving duplicate-rule ordering.
