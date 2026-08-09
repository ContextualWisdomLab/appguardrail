# AppGuardrail test strategy

Tests establish behavior and detector efficacy; file presence, registry counts,
and opaque third-party pass/fail statuses are supporting evidence only.

## Test layers

1. Unit tests exercise normalizers, rules, adapters, auth/role checks, evidence
   validation, migrations, retention, hashing, and report rendering.
2. Integration tests cross real CLI, HTTP, SQLite, filesystem, SARIF, package,
   and workflow boundaries with bounded local fixtures.
3. Security tests cover tenant isolation, SSRF/DNS/redirect behavior, secret
   output, provenance tamper, schema confusion, path handling, and untrusted
   payloads.
4. Operational tests cover idempotency, pagination, timeouts, retries,
   cancellation, recovery, packaging, and rollback contracts.
5. Live read-only audits compare the exact GitHub issue inventory with the
   packaged requirements; they do not replace efficacy tests.

## Detection-efficacy matrix

Every issue claim must execute its callable production adapter through:

| Case | Required result |
|---|---|
| Complete positive evidence | Exact finding/control/dependency/reporting state owned by that condition. |
| Complete negative evidence | `clean` or an explicitly effective control only when evidence is authoritative. |
| Missing required evidence | `unknown`, gate unsatisfied. |
| Malformed or wrong-typed evidence | `unknown`, no exception/fail-open. |
| Extra authoritative field | `unknown` under the closed schema. |
| Wrong producer/run/head/source/digest/HMAC | Provenance failure, gate unsatisfied. |
| Multiple independent causes | All assessments preserved; no last-write or priority collapse. |
| Provider/runner/reporting failure | Operational state, never invented source finding. |

Fixtures must resemble source-system payloads and cross the narrowest real
production boundary. A fixture cannot contain the answer-bearing outcome that
the adapter is supposed to compute.

## Mutation sensitivity

Before accepting a new family or obligation, deliberately invert or remove its
decisive production predicate and demonstrate that the focused test fails;
restore it and demonstrate GREEN. At minimum mutate positive, negative,
missing/malformed, provenance, and gate aggregation paths. Registry completeness
tests cannot earn efficacy credit.

## Coverage and documentation

- Owned production statement and branch coverage: exact 100%, without rounded
  percentages or blanket exclusions.
- Public functions/classes/modules: beginner-readable docstrings; `__main__`
  process guards may use explicit no-cover annotations.
- Changed behavior: RED → minimal GREEN → full regression proof.
- Documentation graph: required files, links, ADR status/index, diagram
  sections, status vocabulary, and implementation ownership are checked.

## Workflow evidence

Actions use immutable pins, least privilege, non-persisted credentials,
hash-locked test dependencies, exact head identity, and explicit timeouts.
Queued, skipped-required, neutral-required, cancelled, absent, stale-head,
synthetic-only, or failed evidence is non-passing.

## Release acceptance

Release requires full CI/security/coverage/docstring/package/SBOM/provenance
evidence, zero valid unresolved critical/high finding, approved migrations and
rollback, accessible UI evidence, exact integrated protected head, independent
review where policy requires it, and protected-main operational verification.
