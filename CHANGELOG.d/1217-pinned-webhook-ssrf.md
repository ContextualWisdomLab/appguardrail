### Fixed

- Webhook delivery now validates every public HTTPS destination against one
  DNS answer set and connects only to those captured addresses, preventing
  validation-to-use rebinding and legacy IPv4-spelling bypasses.
