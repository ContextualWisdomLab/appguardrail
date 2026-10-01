# Python governance resource-bound detectors

**Status:** Source-derived detector slice  
**Rules:** `python-governance-unbounded-json-load`, `python-governance-subprocess-without-timeout`  
**Collected source family:** fast-mlsirm PR #388; AppGuardrail collector issue #791

## Source-authoritative evidence

The failed Strix job in AppGuardrail issue #791 is provenance only. Detector efficacy comes from the source change in `ContextualWisdomLab/fast-mlsirm` and the later protected implementation:

- vulnerable base head: `c8555c3f33a7bc8fdb2e8e0ea0f3cf2bd52ce0b9`;
- vulnerable `scripts/build_pr_queue_governance.py` blob: `3dab225870e5fce806047a622a605b6c451bce59`;
- partial Sentinel repair head: `c9456a0c29c5b0c37cb11867c1a8e605738db40c`;
- partial repair blob: `b016f8c698189d580634b81a1508f567379dcbfc`;
- current protected `main` governance-script blob: `65b8b3b9e1a5c8d68987261987b9e20660e2d1ab`.

The regression corpus stores the detector-relevant function slices copied from those immutable blobs as inert TOML data. Fixed SHA-256 assertions bind every vulnerable, partial-fix, and protected-fix slice before the production rule or scanner entrypoint is exercised. A future fixture edit therefore fails instead of silently changing the source oracle while leaving only the Git object identifiers unchanged.

PR #388 was closed after review because its `path.stat()` then `path.open()` size check was vulnerable to replacement between check and use. Its subprocess timeout additions were explicitly described as directionally correct. Current protected main uses the repository's descriptor-safe `read_json_object` for offline snapshots and bounds the Git metadata child process. The current GitHub-CLI helper has evolved independently, so this detector slice is deliberately source-shaped and does not claim that every current subprocess path is already bounded.

## Detector A — direct governance `json.load`

Python 3.14.6 warns that malicious JSON can consume considerable CPU and memory and recommends limiting the size of data before parsing. The source-derived governance reader opened an arbitrary snapshot path and passed that stream directly to `json.load` with no descriptor-bound size control.

`python-governance-unbounded-json-load` reports the bounded `_read_json(path)` source shape when it opens `path` and performs `json.load` instead of delegating to the reviewed descriptor-safe bounded reader. A separate `path.stat()` check does not suppress the detector because the path can be replaced before the subsequent open.

The rule maps to CWE-400 as the observed availability consequence. CWE 4.20 cautions that CWE-400 should describe incorrect resource-control behavior rather than being used merely because resource consumption is an impact; here the detector requires the concrete unbounded parse operation rather than any generic JSON use.

## Detector B — governance subprocess without timeout

Python's `subprocess.run` accepts a `timeout` parameter and raises `TimeoutExpired` when the child does not terminate within the bound. In CI/governance code, a `gh` child can otherwise hold the worker indefinitely when the CLI or its remote dependency stalls.

`python-governance-subprocess-without-timeout` is restricted to `_run_gh*` functions and a bounded `subprocess.run(...)` call that lacks a `timeout=` keyword. A local formatter subprocess outside this governance function family is deliberately negative.

## Remediation boundary

For JSON artifacts, open the intended object once, validate the opened descriptor as the expected file type, cap bytes read from that same descriptor, and reject oversize input before `json.loads`/`json.load` performs unbounded decoding work.

For child processes, use a finite timeout appropriate to the operation and convert `TimeoutExpired` into explicit fail-closed evidence rather than silently treating missing output as success.

## Declared limitations

These are not general Python resource-exhaustion rules. They do not claim coverage for:

- arbitrary `json.load` in application code;
- JSON depth/shape bounds after a byte-size cap;
- helper-mediated descriptor-safe readers whose behavior is not visible in the source region;
- `Popen`, `asyncio` subprocesses, multiprocessing, or shell scripts;
- non-GitHub governance subprocesses;
- external runner/job timeout policy;
- whether a particular governance snapshot is attacker-controlled in every deployment.

Expand the detector only from a new source-backed weakness and independently reviewed safe boundary.

## APA 7 references

MITRE Corporation. (2026). *CWE-400: Uncontrolled resource consumption* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/400.html

MITRE Corporation. (2026). *CWE-770: Allocation of resources without limits or throttling* (Common Weakness Enumeration Version 4.20). https://cwe.mitre.org/data/definitions/770.html

Python Software Foundation. (2026). *json — JSON encoder and decoder* (Python 3.14.6 documentation). https://docs.python.org/3/library/json.html

Python Software Foundation. (2026). *subprocess — Subprocess management* (Python 3.14.6 documentation). https://docs.python.org/3/library/subprocess.html
