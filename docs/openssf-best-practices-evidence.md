# OpenSSF Best Practices Evidence

AppGuardrail can collect and preserve OpenSSF Best Practices Badge evidence as a normalized governance finding. The feature is designed for buyer diligence and release evidence: it records what the official public service returned at a specific time without treating missing or inaccessible data as proof that a project is not registered.

## What AppGuardrail queries

Live collection uses the OpenSSF Best Practices Badge API's exact-URL project search:

```text
https://www.bestpractices.dev/projects.json?url=<URL-encoded repository URL>
```

The API returns an array of matching projects. AppGuardrail accepts one valid match, treats an empty array as unavailable public evidence, and treats multiple matches as ambiguous. The query uses the documented `.json` URL form; it does not use the HTTP `Accept` header to select a format.

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
| `malformed` | The response was invalid, ambiguous, oversized, redirected, or used an unsupported badge level. |

The badge level is read from the official `badge_level` field. AppGuardrail does not infer a badge from `tiered_percentage`. The percentage is retained only as supporting evidence when it is a valid integer from 0 through 300.

## Live collection

The wheel installs a dedicated command so the evidence collector remains independently usable and can also be imported into an organization service or naruon module:

```bash
appguardrail-openssf-evidence \
  --repository-url https://github.com/ContextualWisdomLab/appguardrail \
  --out reports/openssf-findings.json
```

The output uses the standard `appguardrail.findings.v1` envelope and contains one governance finding. Positive badge evidence is informational. Unavailable, permission-limited, and malformed evidence is a warning for diligence review; it is not a deploy blocker.

Live requests are pinned to the two documented service origins, reject redirects, limit response size, and use a bounded timeout. The collector never copies HTTP error bodies into findings or logs.

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

The same implementation is available as a Python module for minimal environments:

```bash
python -m appguardrail_core.openssf_evidence \
  --repository-url https://github.com/ContextualWisdomLab/appguardrail
```

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

If the report receives no OpenSSF evidence record, it says that no record was supplied. It does not claim that the project is unregistered.

## Official source and attribution

This integration follows the **OpenSSF Best Practices Badge API** documentation:

- <https://github.com/ossf/best-practices-badge/blob/main/docs/api.md>
- <https://www.bestpractices.dev>

The OpenSSF documentation asks API users to provide attribution. Reports and findings therefore retain the official source URL and identify the source as the **OpenSSF Best Practices badge contributors**. Publicly available non-code content is attributed as **CC-BY-3.0+**. Operators should respect the documented rate guidance; requests other than badge images should remain at or below approximately one request per second.
