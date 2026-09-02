"""SSRF guard for outbound requests to a URL supplied in a user request.

Used by /api/fetch-url, which fetches a URL an analyst pastes in and returns
its content. Admin-configured integration targets (MISP, Flowintel, webhook
channels) are deliberately not checked: those are expected to be internal.
"""

import ipaddress
import socket
from urllib.parse import urlsplit


def is_safe_public_url(url: str) -> bool:
    """Return True only for http(s) URLs whose host resolves to public IPs.

    Rejects non-web schemes and any host that resolves to a loopback,
    link-local, private, reserved or multicast address (e.g. cloud metadata at
    169.254.169.254, internal services on 127.0.0.1 or RFC1918 ranges). Every
    resolved address must be global, so a hostname with a mix of public and
    private records is rejected.

    Note: this validates the host at check time. DNS rebinding between this
    check and the actual fetch remains a residual risk; authentication and
    authorization on the calling endpoint are the primary control.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return False
    host = parts.hostname
    if not host:
        return False
    try:
        # A malformed port ("http://host:99999/") makes .port itself raise.
        port = parts.port or (443 if parts.scheme == "https" else 80)
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
