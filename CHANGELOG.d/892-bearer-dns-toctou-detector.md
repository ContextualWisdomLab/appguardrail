## Security

- Add HIGH built-in detector `python-bearer-preflight-dns-toctou` for bearer-authenticated Python `urllib` flows that validate a URL before dispatch but allow the network client to make a second DNS decision. The source-backed regression corpus preserves the pre-PR #898 vulnerable flow and the protected DNS-pinned HTTPS repair for security issue #892.
