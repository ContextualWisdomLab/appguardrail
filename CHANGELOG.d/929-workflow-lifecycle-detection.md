- Add read-only, exact-default-SHA GitHub Actions registry reconciliation and
  structural detection for mutable-branch writers and self-modifying workflows.
- Avoid a false alarm for protected-branch publishers that push with `HEAD:`.
- Preserve both detections when YAML quotes `contents: write` or
  `permissions: write-all` scalars.
- Detect quoted keys, flow-style write permissions, and continued mutable
  pushes, simple event-derived variable indirection, and continued workflow
  mutation without treating comments, echoed commands, run-body permission
  strings, or ambiguous protected-branch refs as executable mutable writes.
- Keep live inventory functional from installed packages, revalidate workflow
  registry identity and state, bound workflow pagination, and atomically
  replace success or failure evidence so stale artifacts cannot contradict the
  current result. Reject aliased artifact paths and bracket both registry reads
  with the exact default-branch SHA.
