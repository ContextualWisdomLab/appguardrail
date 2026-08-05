### Changed

- Reduced repeated scan-root path classification and relative-path allocation in large repository scans while preserving `str` subclass compatibility.
- Restricted bearer-authenticated control-plane uploads and redirects to HTTPS and removed sensitive headers on cross-origin redirects.
