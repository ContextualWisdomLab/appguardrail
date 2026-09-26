### Changed

- Skip the public-reference regex scanner when rule copy has no `[` marker, and
  keep only bracketed OWASP, CWE, and CVE IDs in finding metadata. Unbracketed
  mentions stay out of buyer reports.
