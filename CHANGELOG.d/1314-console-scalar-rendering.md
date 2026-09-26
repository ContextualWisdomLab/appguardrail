### Fixed

- Console dashboard scalar rendering now bounds count fields to non-negative safe
  integers, escapes scan identifiers before HTML attribute interpolation, and
  accepts only own severity-map keys. Invalid, infinite, fractional, negative,
  object, and markup-bearing inputs fail closed to zero or the INFO color
  (PR #1314).
