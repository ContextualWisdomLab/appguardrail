# Python fail-open authentication-secret detector

Added a bounded Python SAST detector for authentication guards that implicitly disable Bearer authentication when a required server token is missing. The candidate is source-backed by NewsDOM's reviewed protected fail-closed remediation, maps the weakness to CWE-306 and OWASP A07:2025, and includes production-scanner positive/fixed-negative regression evidence.
