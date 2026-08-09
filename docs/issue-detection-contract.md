# Issue-derived detection contract

Implementation status: `ACTIVE_PR` #911. See the canonical
[architecture](../ARCHITECTURE.md), [ADR](adr/ADR-0001-issue-complete-detection-contract.md),
[test strategy](TEST_STRATEGY.md), and [traceability matrix](TRACEABILITY.md).

Every GitHub issue in `ContextualWisdomLab/appguardrail` is a retained
AppGuardrail detection requirement. Closed issues and repeated workflow events
remain in scope because they preserve regression targets.

The baseline captured on 2026-08-09 contains **414** issues: 403 organization
security-workflow observations and 11 product or governance requirements. They
map to **17 detector families** and **417 independently auditable claims** in
`appguardrail_core/issue_detection_registry.json`. Issue #132 retains four
independent claims rather than collapsing its redaction, privileged workflow,
release-integrity, and defensive-control obligations.

## Executable contract

Each family declares all of the following:

- an exact Python callable adapter reference and implementation references;
- closed `evidence_fields` and `required_evidence_fields` for its accepted
  evidence schema;
- detected, clean, and unknown outcome states;
- executable **positive, negative, and unknown** fixtures; and
- `no_exclusions: true`.

The loader resolves every declared adapter reference against the closed runtime
callable map. It rejects missing or duplicate issue numbers, empty claims,
unknown families, waiver fields, answer-bearing `state` fixtures, and a family
without all three raw-evidence fixture states. Each issue also carries a
SHA-256 digest of its normalized title and body. Editing a requirement therefore
fails the live audit until its claims and digest are reviewed together. A new
family is unavailable until it is registered in code and the registry at the
same time.

### Closed evidence and executable obligations

`evidence_fields` is a closed allowlist: it names every field an adapter may
interpret for that family. `required_evidence_fields` is the closed subset that
must be present before the family may report a detected, clean, or verified
control outcome. The registry does not infer support from a field name, ignore
an unfamiliar value, or silently fill in an omitted value.

Every claim inherits its detector family's machine-readable `obligations[]`.
An obligation states the specific condition to prove and the family-scoped
evidence fields needed to prove it. Its positive, negative, and unknown
executions must exercise the **whole stated condition**: a fixture that only
proves a convenient sub-signal, or only asserts a final status, does not satisfy
the obligation. This makes the 417 claims independently executable rather than
descriptive annotations on the 414 issues.

Unsupported evidence fields, additional fields outside `evidence_fields`, or
missing required evidence fields always produce an `unknown` outcome with
`gate_satisfied: false`. They cannot be downgraded to clean, treated as an
optional extension, or used to infer a finding. The same fail-closed rule
applies when a declared obligation has no complete positive, negative, and
unknown execution for its condition.

`gate_satisfied` is separate from `confirmed_security_finding`. A failed or
cancelled workflow **does not prove a vulnerability**. Rate limits,
publication failures, timeouts, unclassified cancellations, malformed results,
and unknown evidence all keep `gate_satisfied: false`. An authorization control
that correctly rejects an untrusted dispatch is recorded as a successful
control event rather than a product vulnerability.

Free-form logs can produce bounded operational diagnoses, but cannot confirm a
finding or a successful control. A confirmed finding requires an
`appguardrail.workflow-result-envelope.v1` carrying a valid HMAC-SHA-256
attestation from its source producer. Its `appguardrail.workflow-result.v1`
payload is bound to an exact family-specific producer, workflow run,
40-character head commit, evidence reference, and recomputed payload digest.
The verifier key is a capability provisioned outside result JSON; a Boolean,
matching producer string, or self-computed digest cannot create trust. Raw logs,
keys, and matched secrets are never serialized in the output; the evidence hash
contains only bounded classification identity.

## CLI

Classify a caller-authorized workflow log:

```bash
appguardrail-issue-detection classify-workflow \
  --workflow-name "Strix Security Scan" \
  --job-name strix \
  --conclusion failure \
  --log-file /authorized/path/job.log
```

Supply provenance-bound structured evidence when a source job publishes it:

```bash
export APPGUARDRAIL_WORKFLOW_RESULT_HMAC_KEY="$(base64 < trusted-key-file)"
appguardrail-issue-detection classify-workflow \
  --workflow-name "Strix Security Scan" \
  --job-name strix \
  --conclusion failure \
  --run-id 91554698847 \
  --head-sha 0123456789abcdef0123456789abcdef01234567 \
  --result-file /authorized/path/result.json \
  --log-file /authorized/path/job.log
```

`APPGUARDRAIL_WORKFLOW_RESULT_HMAC_KEY` must decode to at least 32 bytes and be
provisioned by the trusted gate runner, not supplied by the result producer.
AppGuardrail authenticates the envelope metadata in constant time, recomputes
the payload digest, and then checks the run, head, and exact producer mapping.
Missing, weak, malformed, or mismatched key material keeps the gate unsatisfied.

Audit a complete, paginated GitHub issues response:

```bash
appguardrail-issue-detection audit-registry --issues-file /tmp/issues.json
```

The audit exits 0 only when live and registered issue-number sets and
requirement digests are identical. It excludes pull requests returned by
GitHub's Issues API—including connector-normalized `/pull/` URLs—and accepts
both the API's `number` field and normalized `issue_number` records.

## Adding or changing an issue

1. Add the new issue number and at least one independently named claim.
2. Reuse a detector family only when its evidence condition and result contract
   are identical; repeated issues still receive separate mappings.
3. For a new condition, add a callable family, implementation references,
   closed `evidence_fields` and `required_evidence_fields`, and
   positive/negative/unknown executions for every `obligations[]` condition.
4. Run the focused tests and exact statement-coverage gate.
5. Run the live registry audit. Do not mark an issue excluded, duplicate,
   suppressed, waived, or not applicable.

The read-only audit workflow runs for opened, edited, reopened, and closed issue
events, pull requests, manual requests, and a schedule. It pages the complete
open-and-closed issue inventory, so changing the static baseline alone cannot
hide a newly created or materially edited issue.

## Evidence boundary

The central registry contains only issue numbers, normalized requirement
digests, update timestamps, claims, detector contracts, and bounded fixtures.
It does not store issue bodies, source-job logs, tokens, or production
attestation keys. Source repositories remain responsible for authorizing access
to their own logs and for protecting result-attestation key material.

The inventory audit follows the
[GitHub Issues REST API](https://docs.github.com/en/rest/issues/issues#list-repository-issues).
SARIF-producing tools should retain the
[OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
tool, rule, location, and fingerprint identity when publishing a structured
AppGuardrail workflow result.
