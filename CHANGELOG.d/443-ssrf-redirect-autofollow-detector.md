### Security

- Add the bounded `python-ssrf-redirect-autofollow-after-validation` SAST rule for Python `urllib.request` flows that validate only the initial outbound URL and then call redirect-following `urlopen`, with source-authoritative vulnerable/fixed AppGuardrail replays and CWE-918 / OWASP A10:2021 metadata.
