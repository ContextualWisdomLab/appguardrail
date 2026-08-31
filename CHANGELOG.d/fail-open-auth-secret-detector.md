# Python fail-open authentication-secret detector

Added a bounded Python SAST detector for authentication guards that implicitly disable Bearer authentication when a required server token is missing. The candidate is source-backed by NewsDOM's reviewed protected fail-closed remediation, maps the weakness to CWE-306 and OWASP A07:2025, and includes production-scanner positive/fixed-negative regression evidence.

Review hardening now rejects `Bearer` evidence found only in comments, log strings, or a later sibling/outer class while retaining vulnerable guards that declare a nested class inside the authentication function. Public taxonomy metadata stays single-sourced in the parsed rule message, and the finding is classified as an authentication/authorization control issue with fail-closed operator guidance instead of hardcoded-secret rotation advice.
