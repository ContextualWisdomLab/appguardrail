### Added

- Add HIGH built-in `python-ssrf-empty-host-fail-open` detection (CWE-918) for Python URL validators that derive a possibly empty hostname, reach DNS resolution, ignore `socket.gaierror`, and later return success without a dominating empty-host rejection. Historical vulnerable/fixed fixtures and production-scanner regressions cover nested and same-line conditional guards, fail-closed DNS errors, equivalent guards before success, sibling-function boundaries, and unrelated DNS probes.
