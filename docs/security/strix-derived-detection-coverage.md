# Strix-derived detection coverage

Updated: 2026-07-11

This inventory separates validated vulnerability patterns from scanner self-hits
and incomplete reconnaissance. It is intentionally evidence-based: a Strix
report mentioning a risky class is not treated as a confirmed AppGuardrail
runtime vulnerability unless the source-to-sink path was independently fixed or
reproduced.

## Evidence reviewed

- PR [#135](https://github.com/ContextualWisdomLab/appguardrail/pull/135)
  merged the first Strix-derived rule set: browser storage and DOM XSS sinks,
  frontend DSN exposure, upload filename traversal, dynamic SQL, JWT algorithm
  pinning, subprocess/CORS risks, client-controlled identity, CSRF markers, and
  internal exception chaining.
- Recent non-expired `strix-reports` artifacts were sampled across 63 unique
  report contents from AppGuardrail workflow runs. Only two unique sampled
  artifacts contained canonical `vulnerabilities.json` records:
  [run 28778327178](https://github.com/ContextualWisdomLab/appguardrail/actions/runs/28778327178)
  and
  [run 28779945084](https://github.com/ContextualWisdomLab/appguardrail/actions/runs/28779945084).
  Those records described the new Vue/Svelte and Ansible *rule definitions*
  being reviewed, not exploitable AppGuardrail runtime paths. They are retained
  as scanner self-hit/fixture evidence, not promoted as product vulnerabilities.
- PR [#145](https://github.com/ContextualWisdomLab/appguardrail/pull/145)
  proposed a broad dynamic-URL SSRF regex but was closed as superseded. The
  blanket pattern was not carried forward because ordinary dynamic service URLs
  are not enough to prove attacker control.
- Repeated AppGuardrail security fixes established concrete SSRF/LFI failure
  modes: unsafe URL schemes and redirects
  ([#158](https://github.com/ContextualWisdomLab/appguardrail/pull/158),
  [#173](https://github.com/ContextualWisdomLab/appguardrail/pull/173),
  [#280](https://github.com/ContextualWisdomLab/appguardrail/pull/280)),
  destination/DNS validation gaps
  ([#266](https://github.com/ContextualWisdomLab/appguardrail/pull/266)), and
  IPv4-only resolution that allowed IPv6 bypass
  ([#284](https://github.com/ContextualWisdomLab/appguardrail/pull/284)).

## Coverage mapping

| Evidence-backed weakness | AppGuardrail rule | Precision boundary |
| --- | --- | --- |
| Python request input passed directly to a network client | `python-request-input-ssrf` | Requires a direct HTTP request source at the sink |
| Node request input passed directly to `fetch` or Axios | `node-request-input-ssrf` | Requires `req`/`request` query, body, or params at the sink |
| HTTP(S) scheme check used as the only SSRF guard | `python-scheme-only-ssrf-validation` | Requires URL parsing, a scheme allowlist, a later network sink, and no nearby address control |
| IPv4-only DNS lookup inside a URL/host safety helper | `python-ipv4-only-ssrf-validation` | Requires `gethostbyname` inside a named URL/host validation function |
| Redirect `Location` fetched without revalidation | `python-unvalidated-redirect-ssrf` | Requires header extraction followed by a network fetch and no nearby safety helper |

The rules deliberately do not flag every variable, f-string, or template literal
used as a URL. Regex-only scanning cannot prove attacker control for those
cases, and AppGuardrail already delegates broader data-flow analysis to its
external Semgrep/CodeQL integration paths.

## Verification contract

`tests/test_ssrf_rules.py` supplies one malicious example and one legitimate
control for every rule family. The repository self-scan must classify examples,
tests, docs, and `scanner/rules/` matches as non-deploy-blocking fixture context;
application-code matches remain deploy-blocking at `HIGH` or `CRITICAL`.
