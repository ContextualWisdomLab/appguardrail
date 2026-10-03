### Fixed

- Console dashboard scalar rendering now bounds count fields to non-negative safe
  integers and escapes scan identifiers before HTML attribute interpolation.
  Invalid, infinite, fractional, negative, object, and markup-bearing inputs fail
  closed to zero. Own-property severity selection is inherited from the stacked
  PR #1260 repair (PR #1314).
