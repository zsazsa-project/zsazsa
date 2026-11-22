"""SSRF guard for outbound requests to a URL supplied in a user request.

Used by /api/fetch-url, which fetches a URL an analyst pastes in and returns
its content. Admin-configured integration targets (MISP, Flowintel, webhook
channels) are deliberately not checked: those are expected to be internal and
are reachable only to a site administrator.

resolve_public_url resolves the host once and returns the addresses it checked,
so the caller can pin the connection to them. Pinning closes the DNS-rebinding
window: without it, the host is validated here and then resolved a second time
by the HTTP client, and a name answering public now and internal a moment later
(TTL 0) would pass the check and still be fetched (CWE-367).
"""

import ipaddress
import socket
from urllib.parse import urlsplit


def resolve_public_url(url: str):
    """Resolve an http(s) URL, returning (host, port, ips) when it is public.

    Returns None for a non-web scheme, a URL that will not parse, a host that
    does not resolve, or any host that resolves to a loopback, link-local,
    private, reserved or multicast address (e.g. cloud metadata at
    169.254.169.254, internal services on 127.0.0.1 or RFC1918 ranges). Every
    resolved address must be global, so a hostname with a mix of public and
    private records is rejected.

    On success ``ips`` is the de-duplicated list of resolved addresses and
    ``port`` is the effective port (the URL's own, or 80/443 for the scheme).
    The caller pins the fetch to exactly these addresses.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https"):
        return None
    host = parts.hostname
    if not host:
        return None
    try:
        # A malformed port ("http://host:99999/") makes .port itself raise.
        port = parts.port or (443 if parts.scheme == "https" else 80)
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, ValueError):
        return None
    if not infos:
        return None
    ips: list[str] = []
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return None
        if not ip.is_global or ip.is_multicast:
            return None
        if addr not in ips:
            ips.append(addr)
    return host, port, ips


def pinned_curl_options(host: str, port: int, ips: list[str]) -> dict:
    """curl_cffi options that pin a fetch to the addresses resolve_public_url
    checked, so the client's own DNS lookup cannot rebind the host to an
    internal address between the check and the fetch (CWE-367). An IP-literal
    host has no name to rebind, so it is fetched as it is."""
    from curl_cffi import CurlOpt

    try:
        ipaddress.ip_address(host)
        return {}
    except ValueError:
        return {CurlOpt.RESOLVE: [f"{host}:{port}:{','.join(ips)}"]}


def is_safe_public_url(url: str) -> bool:
    """Return True only for http(s) URLs whose host resolves to public IPs.

    A thin wrapper over resolve_public_url for callers that only need the yes/no
    answer (and do not pin the connection).
    """
    return resolve_public_url(url) is not None
