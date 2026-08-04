# OpenSSF Best Practices Evidence

AppGuardrail can collect and preserve OpenSSF Best Practices Badge evidence as a normalized governance finding. The feature is designed for buyer diligence and release evidence: it records what the official public service returned at a specific time without treating missing or inaccessible data as proof that a project is not registered.

## What AppGuardrail queries

Live collection uses the OpenSSF Best Practices Badge API's exact-URL project search:

```text
https://www.bestpractices.dev/projects.json?url=<URL-encoded repository URL>
```

The API returns an array of matching projects. AppGuardrail accepts one valid match, treats an empty array as unavailable public evidence, and treats multiple matches as ambiguous. The query uses the documented `.json` URL form; it does not use the HTTP `Accept` header to select a format.

A returned project is accepted only when its `repo_url` or `homepage_url` matches the exact normalized URL that was queried. A response containing an unrelated project ID or badge level is classified as `malformed` instead of becoming affirmative evidence.

The current service origin is:

```text
https://www.bestpractices.dev
```

The historical service origin is also recognized for migration-compatible evidence:

```text
https://bestpractices.coreinfrastructure.org
```

AppGuardrail queries the historical origin only after the current origin returns a valid empty array. Permission failures, malformed responses, redirects, rate limiting, and service failures do not trigger a historical lookup because those states do not establish that the current service has no matching record.

## Evidence states

| State | Meaning |
|---|---|
| `in_progress` | The official project record reports work toward the passing badge. |
| `passing` | The official project record reports the passing badge. |
| `silver` | The official project record reports the silver badge. |
| `gold` | The official project record reports the gold badge. |
| `unavailable` | No matching public evidence was observed, or the public service could not be reached. This does not prove non-registration. |
| `permission_limited` | The service returned an access-limited response, so no badge claim was made. |
| `malformed` | The response was invalid, ambiguous, oversized, redirected, used an unsupported badge level, or did not carry the queried URL identity. |

The badge level is read from the official `badge_level` field. AppGuardrail does not infer a badge from `tiered_percentage`. The percentage is retained only as supporting evidence when it is a valid integer from 0 through 300.

## Live collection

The wheel installs a dedicated command so the evidence collector remains independently usable and can also be imported into an organization service or naruon module:

```bash
appguardrail-openssf-evidence \
  --repository-url https://github.com/ContextualWisdomLab/appguardrail \
  --out reports/openssf-findings.json
```

The output uses the standard `appguardrail.findings.v1` envelope and contains one governance finding. Positive badge evidence is informational. Unavailable, permission-limited, and malformed evidence is a warning for diligence review; it is not a deploy blocker.

Live requests are pinned to the two documented service origins, reject redirects, require a JSON media type, limit response size to 1,000,000 bytes, and use a bounded timeout. The collector closes HTTP error streams and never copies response bodies into findings or logs.

## Offline and reproducible ingestion

Save the exact JSON array returned by the official URL lookup and ingest it later:

```bash
appguardrail-openssf-evidence \
  --repository-url https://github.com/ContextualWisdomLab/appguardrail \
  --source-json evidence/projects.json \
  --verified-at 2026-08-04T09:00:00Z \
  --out reports/openssf-findings.json
```

For a response saved from the historical service, add:

```bash
--source-origin https://bestpractices.coreinfrastructure.org
```

`--verified-at` makes evidence reconstruction deterministic. It must use UTC second precision (`YYYY-MM-DDTHH:MM:SSZ`). Without it, AppGuardrail records the current UTC timestamp at second precision.

Offline input follows the same 1,000,000-byte bound and strict UTF-8/JSON decoding contract as live collection. Invalid, recursively pathological, or oversized local evidence returns a concise non-zero command result rather than exhausting memory or publishing an unverifiable badge claim.

The same implementation is available as a Python module for minimal environments:

```bash
python -m appguardrail_core.openssf_evidence \
  --repository-url https://github.com/ContextualWisdomLab/appguardrail
```

The package's supported interpreter floor is Python 3.11. The main repository test matrix exercises Python 3.11 and Python 3.13.

## Buyer-diligence reports

Pass the resulting findings file to the existing report command:

```bash
appguardrail report buyer-diligence \
  --findings reports/openssf-findings.json \
  --out reports/buyer-diligence.md
```

The report includes an **OpenSSF Best Practices Evidence** table containing:

- repository URL;
- verification state;
- verified badge tier, if any;
- verification timestamp; and
- canonical public project evidence URL, if one was established.

The report revalidates status, tier, project ID, and canonical project URL before displaying affirmative evidence. Inconsistent externally supplied metadata is rendered as malformed and never as a badge claim.

If the report receives no OpenSSF evidence record, it says that no record was supplied. It does not claim that the project is unregistered.

## Official source, attribution, and license policy

This integration follows the **OpenSSF Best Practices Badge API** documentation:

- <https://github.com/ossf/best-practices-badge/blob/main/docs/api.md>
- <https://www.bestpractices.dev>

The OpenSSF service asks API users to provide attribution. Reports and findings identify the source as the **OpenSSF Best Practices badge contributors**.

The current website policy states that publicly available non-code content added or edited after **2024-08-23** is released under **CDLA-Permissive-2.0**. Earlier contributions were licensed under **CC-BY-3.0** or **CC-BY-3.0+**. AppGuardrail records this date-dependent policy rather than claiming that all returned data uses one historical license.

Operators should respect the documented rate guidance; requests other than badge images should remain at or below approximately one request per second.

## Standards basis

The evidence boundary follows RFC 3986 when separating URI scheme, authority, path, query, fragment, and user information. Canonical public project evidence therefore rejects credentials, unexpected ports, query strings, and fragments instead of treating a partially matching URL as trustworthy.

The transport accepts `application/json` and registered `application/*+json` structured media types in accordance with RFC 6839. JSON input is decoded as UTF-8 and parsed under the interoperable JSON grammar defined by RFC 8259; malformed or excessively nested input fails closed without creating affirmative evidence.

## References (APA 7th)

Berners-Lee, T., Fielding, R., & Masinter, L. (2005). *Uniform Resource Identifier (URI): Generic syntax* (RFC 3986). RFC Editor. https://doi.org/10.17487/RFC3986

Bray, T. (2017). *The JavaScript Object Notation (JSON) data interchange format* (RFC 8259). RFC Editor. https://doi.org/10.17487/RFC8259

Hansen, T., & Melnikov, A. (2013). *Additional media type structured syntax suffixes* (RFC 6839). RFC Editor. https://doi.org/10.17487/RFC6839

Open Source Security Foundation. (n.d.). *Application programming interface (API).* GitHub. Retrieved August 4, 2026, from https://github.com/ossf/best-practices-badge/blob/main/docs/api.md

Open Source Security Foundation. (n.d.). *OpenSSF Best Practices Badge.* Retrieved August 4, 2026, from https://www.bestpractices.dev/
