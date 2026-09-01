"""Shared SSRF guard for outbound HTTP requests to admin-configured URLs.

Used by any code path that sends a request to a URL supplied through the
config UI (webhooks, Flowintel instances, ad-hoc fetches) so a single check
protects internal services and cloud metadata endpoints consistently.
"""

import ipaddress
import socket
from urllib.parse import urlsplit


def is_safe_public_url(url: str) -> bool:
    """Return True only for http(s) URLs whose host resolves to public IPs.

    Guards outbound requests against SSRF: rejects non-web schemes and any
    host that resolves to a loopback, link-local, private, reserved or
    multicast address (e.g. cloud metadata at 169.254.169.254, internal
    services on 127.0.0.1 or RFC1918 ranges). Every resolved address must be
    global, so a hostname with a mix of public and private records is rejected.

    Note: this validates the host at check time. DNS rebinding between this
    check and the actual request remains a residual risk; authentication and
    authorization on the calling endpoint are the primary control.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return False
    host = parts.hostname
    if not host:
        return False
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, ValueError):
        return False
    if not infos:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if not ip.is_global or ip.is_multicast:
            return False
    return True
