# Tenant Retention And Tamper-Evident Audit Policy

AppGuardrail's retention and audit core gives standalone deployments, CWL organization services, and naruon modules one deterministic policy language. It separates policy decisions from SQLite, HTTP, and deployment-specific authorization so the same controls can later be enforced by the embedded control plane or a managed service.

The durations below are **product defaults, not legal advice**. A buyer must map them to applicable law, contracts, incident-response obligations, litigation holds, backup architecture, and sector-specific rules. GDPR storage limitation requires personal data to be kept no longer than necessary for its purpose, but it does not prescribe one universal number of days. NIST controls likewise require organizations to define, protect, retain, and dispose of records according to their risk and obligations rather than copying one vendor default.

## Phase 1 scope

This phase adds dependency-free primitives for:

- a tenant-scoped, revisioned retention policy;
- optimistic concurrency for owner-approved policy changes;
- deterministic UTC cutoffs under an injected `as_of` time;
- purge previews bound to policy revision, legal-hold revision, cutoffs, and counts;
- stale-preview and tampering detection;
- non-secret purge receipts that require a final current-revision check;
- append-oriented, tenant-local SHA-256 audit chains;
- canonical event hashing, chain verification, and optional trusted head checkpoints; and
- mandatory redaction of secret-bearing and raw customer-evidence fields before hashing and export.

This phase does **not** yet delete rows, expose an HTTP retention endpoint, migrate the control-plane database, or claim that any audit record is physically immutable. Those capabilities are bounded follow-up slices under issue #871.

## Product defaults

| Data class | Default | Intended product purpose |
|---|---:|---|
| Scan history | 90 days | Recent trend, regression, and incident context without indefinite customer-code retention. |
| Audit events | 365 days | A longer accountability trail for privileged governance actions. |
| Access-key metadata | 365 days | Key lifecycle evidence without retaining plaintext keys. |
| Webhook metadata | 365 days | Configuration-change evidence without storing credentials in audit payloads. |
| Suppression evidence | 365 days | Risk-acceptance history and expiry evidence. |

Every duration must be an integer from 1 through 3,650 days. These bounds limit accidental immediate destruction and accidental indefinite retention while allowing a deployment to choose a longer, documented policy. Legal hold is modeled separately and overrides eligibility for deletion.

## Optimistic concurrency

A `RetentionPolicy` has a monotonically increasing revision. An owner update supplies the positive integer revision it observed. A mismatch raises `RetentionPolicyConflict` rather than silently overwriting a newer decision. Boolean values are rejected even though Python normally compares `True` equal to `1`. Persistence adapters must perform the same comparison in one transaction.

Only duration fields are mutable through `update_retention_policy`. Tenant identity, current revision, and audit identity are controlled by the caller and cannot be smuggled through the change object.

## Deterministic purge preview

`build_purge_preview` computes all cutoffs from one canonical UTC instant. It binds these values into a SHA-256 preview hash:

- tenant identifier;
- preview identifier;
- policy revision;
- legal-hold revision;
- creation time;
- all category cutoffs;
- eligible row counts; and
- legal-hold exclusion counts.

A persistence adapter must calculate counts without deleting data. Before execution it must call `verify_purge_preview` against the current policy and legal-hold revisions, then repeat or otherwise transactionally protect eligibility checks. `create_purge_receipt` requires those same current revisions and refuses a receipt whose execution time precedes preview creation. If either revision changed, the preview is stale and no receipt or deletion evidence may be created.

Purge execution must be idempotent. A retry of the same completed preview returns the existing receipt. A request using a stale preview must fail closed. The eventual SQLite adapter will use one atomic transaction for deletion, audit event, and receipt so a crash commits all three or none.

## Legal hold

A legal hold is a tenant-scoped exclusion, not an extension hidden inside a retention duration. It must have a revision, documented reason, authorized actor, creation time, and bounded scope. Applying, changing, or releasing a hold increments the legal-hold revision and invalidates older purge previews.

The core preview records held counts, but Phase 1 does not define the persistence schema. Phase 2 will add descriptive database objects and migrate legacy one-word table names before storing holds.

## Tamper-evident audit chain

`create_audit_event` creates a tenant-local event whose SHA-256 hash commits to:

- tenant identifier;
- sequence number;
- event identifier and type;
- actor and request correlation identifiers;
- canonical UTC event time;
- a non-secret summary; and
- the previous event hash.

The first event links to a fixed all-zero genesis hash. `verify_audit_chain` detects mutation, internal deletion, reordering, cross-tenant substitution, broken predecessor links, and sequence gaps. A hash chain by itself cannot prove that the final event was not truncated. When an independently protected count or chain-head digest is available, pass `expected_event_count`, `expected_head_hash`, or both so tail deletion also fails closed.

A hash chain is **tamper-evident, not physically immutable**. A malicious administrator who can replace an entire database and all trusted checkpoints could recompute a new chain. Phase 2 will add append-only SQLite triggers, and later managed deployments should checkpoint chain heads to an independently controlled evidence store.

## Secret and evidence minimization

Audit summaries intentionally record decisions, not customer payloads. Keys that name API keys, authorization values, credentials, passwords, tokens, secrets, webhook URLs, raw findings, snippets, or raw evidence are redacted before hashing. Secret-like text such as bearer credentials, `agk_` keys, Anthropic/OpenAI `sk-` tokens, GitHub `ghp_` tokens, and `github_pat_` credentials is also redacted. Exports re-sanitize the event summary so post-construction mutation cannot inject plaintext credentials into a report.

The core rejects floating-point values, duplicate keys after whitespace normalization, and non-string object keys so every committed event has one deterministic JSON representation. It limits nesting depth and encoded size to prevent audit logging from becoming a denial-of-service path.

The following material must never appear in an audit summary or buyer report:

- plaintext API keys;
- `Authorization` headers;
- webhook credentials or credential-bearing URLs;
- findings snippets or customer code;
- raw suppression evidence; and
- deleted row bodies.

## Standards mapping

| Product behavior | Standards rationale |
|---|---|
| Event types, actor identity, time, outcome summaries, and correlation | NIST SP 800-53 AU-2, AU-3, AU-8, and AU-12 require defined, content-rich, time-correlated audit records. |
| Restricted audit mutation, trusted checkpoints, and tamper detection | NIST SP 800-53 AU-9 requires protection of audit information and tools. |
| Configurable audit retention | NIST SP 800-53 AU-11 and NIST SP 800-92 support organization-defined retention and log-management lifecycle practices. |
| Data retention and disposal policy | NIST SP 800-53 SI-12 requires managing and disposing of information according to policy and requirements. |
| Storage limitation and accountability | GDPR Article 5(1)(e) and Article 5(2). |
| Erasure with documented exceptions | GDPR Article 17. |
| Risk-based information-security management | ISO/IEC 27001:2022. |

## Operational limits

- SHA-256 chaining provides integrity evidence, not non-repudiation or independent timestamp authority.
- Tail-truncation detection depends on a separately protected count or head-hash checkpoint.
- Product defaults do not supersede legal or contractual retention requirements.
- Phase 1 does not delete persisted data.
- Database backups and replicas require separate expiry and legal-hold procedures.
- Audit-event retention may need to exceed scan retention to preserve accountability.
- A managed multi-region service must define clock discipline, external checkpoints, disaster recovery, and data-residency rules beyond this embedded core.

## References (APA 7th)

European Parliament & Council of the European Union. (2016). *Regulation (EU) 2016/679 of 27 April 2016 (General Data Protection Regulation).* Official Journal of the European Union. https://eur-lex.europa.eu/eli/reg/2016/679/oj

International Organization for Standardization. (2022). *ISO/IEC 27001:2022—Information security, cybersecurity and privacy protection—Information security management systems—Requirements.* https://www.iso.org/standard/27001

Joint Task Force. (2020). *Security and privacy controls for information systems and organizations* (NIST Special Publication 800-53, Rev. 5). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-53r5

Kent, K., & Souppaya, M. (2006). *Guide to computer security log management* (NIST Special Publication 800-92). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-92
