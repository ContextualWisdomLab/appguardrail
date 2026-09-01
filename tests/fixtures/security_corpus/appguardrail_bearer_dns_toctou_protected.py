"""Protected AppGuardrail repair for bearer-authenticated DNS rebinding."""


def push_scan(url, payload, api_key):
    """Dispatch through the reviewed transport that pins validated addresses."""
    endpoint = url.rstrip("/") + "/api/v1/scans"
    return post_json_pinned_https(
        endpoint,
        payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        timeout=15,
    )
