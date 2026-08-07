### Security

- Added DNS-pinned public HTTPS delivery for bearer-authenticated control-plane scan uploads, preserving the original hostname for TLS SNI and certificate verification while connecting only to the exact globally routable addresses admitted by validation.
- Restricted credential-bearing redirects to HTTP 307 and 308, revalidated every hop, and removed `Authorization` and `Proxy-Authorization` case-insensitively whenever the normalized HTTPS origin changes.
- Added bounded timeout, redirect-count, response-size, JSON, and non-secret error contracts plus exact statement-coverage and operator documentation for standalone, organization-service, and naruon reuse.
