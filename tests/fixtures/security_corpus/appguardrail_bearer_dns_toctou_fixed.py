"""Reviewed AppGuardrail repair for bearer-authenticated DNS rebinding."""


def push_scan(url, payload, api_key):
    """Dispatch through the transport that pins the validated address set."""
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
