"""Reviewed fixed AppGuardrail empty-host SSRF validator regression fixture."""


def is_safe_url(url: str) -> bool:
    import ipaddress
    import socket
    import urllib.parse

    parsed = urllib.parse.urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return False

    host = (parsed.hostname or "").lower()
    if not host:
        return False
    raw = host.split("%", 1)[0].strip("[]")

    try:
        ip = ipaddress.ip_address(raw)
        if ip.is_private:
            return False
    except ValueError:
        pass

    try:
        resolved = socket.getaddrinfo(raw, None)
        for entry in resolved:
            if ipaddress.ip_address(entry[4][0]).is_private:
                return False
    except socket.gaierror:
        pass

    return True
