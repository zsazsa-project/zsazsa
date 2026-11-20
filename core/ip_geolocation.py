"""Where an IP address is, by country, from CIRCL's ip.circl.lu.

The service answers one address per request, with the country it is announced
from and that country's average position, which is where the pew-pew map puts
it. Callers decide what may be sent: this module only refuses an address that
is not on the public internet, which would tell CIRCL something about the
networks zsazsa sees and is never anywhere on a map anyway.
"""

import ipaddress
import logging

import requests

logger = logging.getLogger(__name__)

_URL = "https://ip.circl.lu/geolookup/{}"
_TIMEOUT = 10


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address((value or "").strip()).is_global
    except ValueError:
        return False


def lookup(ip: str, session=None) -> dict | None:
    """{"country", "name", "lat", "lon"} for an address, {} when the service
    does not know it or it is not a public address, and None when the service
    could not be asked, so the caller tries again later."""
    ip = (ip or "").strip()
    if not is_public_ip(ip):
        return {}
    try:
        r = (session or requests).get(_URL.format(ip), timeout=_TIMEOUT,
                                      headers={"Accept": "application/json"})
        if r.status_code == 422:
            return {}
        if r.status_code != 200:
            logger.warning("IP geolocation for %s answered %s", ip, r.status_code)
            return None
        return _parse(r.json())
    except Exception as exc:
        logger.warning("IP geolocation for %s failed: %s", ip, exc)
        return None


def _parse(data) -> dict:
    """The first answer that names a country and its position."""
    for result in data if isinstance(data, list) else []:
        code = ((result or {}).get("country") or {}).get("iso_code") or ""
        info = (result or {}).get("country_info") or {}
        try:
            lat = float(info["Latitude (average)"])
            lon = float(info["Longitude (average)"])
        except (KeyError, TypeError, ValueError):
            continue
        if len(code) == 2 and code.isalpha():
            return {"country": code.upper(), "name": info.get("Country") or code.upper(), "lat": lat, "lon": lon}
    return {}
