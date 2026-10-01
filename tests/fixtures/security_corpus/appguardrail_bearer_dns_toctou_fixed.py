"""Minimal repaired oracle for bearer-authenticated DNS rebinding TOCTOU."""


def push_scan(url, payload, api_key):
    """Keep the vulnerable shape but make connection reuse validated addresses."""
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
    opener = PinnedHTTPSOpener.from_validated_url(url)
    return opener.open(req, timeout=15)
