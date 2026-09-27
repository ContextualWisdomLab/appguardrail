### Changed

- Preserve the bracketed public-reference contract while deduplicating extracted
  and merged references with insertion-ordered explicit loops, avoiding generator
  setup in the measured hot path.
