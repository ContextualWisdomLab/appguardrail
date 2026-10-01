"""Historical AppGuardrail bearer push shape vulnerable to DNS rebinding TOCTOU."""


def push_scan(url, payload, api_key):
    """Validate once, then let urllib resolve again while carrying a bearer token."""
    if not api_key:
        return None
    if not _is_safe_url(url):
        return None

    endpoint = url.rstrip("/") + "/api/v1/scans"
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    try:
        opener = urllib.request.build_opener(SafeRedirectHandler())
        with (
            opener.open(req, timeout=15) as response
        ):
            return response.read()
    except urllib.error.URLError:
        return None
