### Changed

- Reduced repeated scan-root file classification and relative-path allocation in large repository scans while retaining a one-time fallback for standalone `_scan_file` callers.
- Preserved the public `str | Path` contract, including `str` subclasses, while using allocation-light basename and suffix parsing in language detection.
- Restricted bearer-authenticated control-plane uploads and redirects to public HTTPS, rejected transport downgrades, and removed sensitive authorization headers from cross-origin redirects.
- Limited authentication-deferral findings to source comments so executable hardening such as removing `Authorization` headers is not misclassified as deferred authentication work.
