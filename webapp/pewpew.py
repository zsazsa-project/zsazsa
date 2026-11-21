"""What the pew-pew map shows: the indicators zsazsa collected in a window of
days, from the collection cache, with the means that brought each in, where it
is, and the PIR, GIR or RFI it falls under.

An address is where ip.circl.lu says it is; a domain, hostname or URL is where
its top-level domain says, when that is a country code.
An indicator is caught when its event matches an active PIR or GIR, the same
match the collection page makes. An open RFI linked to that PIR or GIR is named
with it.
Nothing here asks ip.circl.lu: the cache worker looks addresses up, and one it
has not looked up yet, or may not send, lands in the litter box.
"""

import hashlib
import logging
import re
import time
from collections import Counter
from datetime import date, timedelta
from urllib.parse import urlsplit

from core import tld_countries
from webapp import collection_cache, matching, misp_store

logger = logging.getLogger(__name__)

WINDOWS = (1, 7, 30)
DEFAULT_WINDOW = 7
# The TLP levels the map can be asked to show. AMBER+STRICT and RED are never on it.
MAP_TLP_LEVELS = ("clear", "green", "amber")
DEFAULT_TLP = "clear"

# The collection means, in the order the page lists them.
MEANS = {
    "scraper": "MISP scraper",
    "misp": "Other MISP servers",
    "newsletter": "Newsletters",
    "manual": "Manual entries",
}
NEWSLETTER_TAG = 'zsazsa:source-type="newsletter"'
# What "Exclude hashes" leaves out.
HASH_TYPES = ("md5", "sha1", "sha256")
# The types placed by their top-level domain.
HOST_TYPES = ("domain", "hostname", "url")
# The newest indicators the page replays; more would only make the loop longer.
# The counts cover them all.
_MAX_INDICATORS = 800
# Far more events than any window holds, so the window decides, not this.
_MAX_EVENTS = 5000


def means_of(event) -> str:
    source_id = event["source_id"]
    if source_id == "scraper":
        return "scraper"
    if source_id.startswith("manual-"):
        return "newsletter" if NEWSLETTER_TAG in (event.get("tags") or []) else "manual"
    return "misp"


def defang(type_: str, value: str) -> str:
    """The value as it is safe to show: no dot or scheme a viewer can follow."""
    if type_ in HASH_TYPES or type_ == "vulnerability":
        return value
    return re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE).replace(".", "[.]")


def _jitter(ip: str) -> tuple:
    """A small, steady offset for an address, so the addresses of one country,
    which all have its centre as their position, do not land on one point."""
    digest = hashlib.sha256(ip.encode()).digest()
    return (digest[0] / 255 - .5) * 3, (digest[1] / 255 - .5) * 3


def _tld(type_: str, value: str) -> str:
    """The top-level domain of a domain, hostname or URL, empty when it has none."""
    host = value
    if type_ == "url":
        try:
            host = urlsplit(value if "://" in value else "//" + value).hostname or ""
        except ValueError:
            return ""
    host = host.lower().rstrip(".")
    return host.rpartition(".")[2] if "." in host else ""


def _catches(events) -> tuple:
    """({event uuid: [requirement and RFI ids]}, {id: {"kind", "label"}}) for
    the events in scope."""
    pirs, girs = matching.get_requirements()
    matched = matching.match_events(events, pirs, girs)
    by_requirement = {}
    try:
        for rfi in misp_store.list_rfis():
            if rfi.status not in misp_store.RFI_OPEN_STATUSES:
                continue
            for linked in (rfi.linked_pir_uuid, rfi.linked_gir_uuid):
                if linked:
                    by_requirement.setdefault(linked, []).append(rfi)
    except Exception as exc:
        logger.warning("pew-pew map: could not read the RFIs: %s", exc)
    catches, names = {}, {}
    for uuid, matches in matched.items():
        ids = [m["id"] for m in matches if m["id"]]
        for m in matches:
            if m["id"]:
                names[m["id"]] = {"kind": m["type"].upper(), "label": m["label"]}
        for m in matches:
            for rfi in by_requirement.get(m["uuid"], []):
                ids.append(rfi.rfi_id)
                names[rfi.rfi_id] = {"kind": "RFI", "label": (getattr(rfi, "question", "") or "")[:120]}
        catches[uuid] = list(dict.fromkeys(ids))
    return catches, names


def map_data(days: int = DEFAULT_WINDOW, tlp: str = DEFAULT_TLP, exclude_hashes: bool = False) -> dict:
    """The indicators of the last ``days`` days up to ``tlp``, oldest first,
    without file hashes when ``exclude_hashes``, and the counts the page shows
    above the map."""
    days = days if days in WINDOWS else DEFAULT_WINDOW
    tlp = tlp if tlp in MAP_TLP_LEVELS else DEFAULT_TLP
    allowed = MAP_TLP_LEVELS[:MAP_TLP_LEVELS.index(tlp) + 1]
    cutoff = (date.today() - timedelta(days=days - 1)).isoformat()

    events = collection_cache.get_events(collection_cache.cached_source_ids(), [], _MAX_EVENTS)
    events = [e for e in events if (e.get("date") or "") >= cutoff]
    event_tlps = {(e["source_id"], e["uuid"]): collection_cache.event_tlp(e["tags"]) for e in events}
    events = [e for e in events if event_tlps[(e["source_id"], e["uuid"])] in allowed]
    by_key = {(e["source_id"], e["uuid"]): e for e in events}

    rows = collection_cache.event_indicators(events)
    if exclude_hashes:
        rows = [r for r in rows if r["type"] not in HASH_TYPES]
    rows.sort(key=lambda r: r["timestamp"] or 0)
    ips = {r["value"]: collection_cache.indicator_ip(r["type"], r["value"])
           for r in rows if r["type"] in collection_cache.IP_TYPES}
    places = collection_cache.ip_locations(ips.values())
    catches, names = _catches([by_key[k] for k in {(r["source_id"], r["event_uuid"]) for r in rows}])
    labels = collection_cache.source_labels()

    indicators = []
    for r in rows:
        key = (r["source_id"], r["event_uuid"])
        event, event_tlp = by_key[key], event_tlps[key]
        item = {
            "ts": r["timestamp"],
            "means": means_of(event),
            "source": collection_cache.source_label(r["source_id"], labels),
            "type": r["type"],
            "value": defang(r["type"], r["value"]),
            "tlp": event_tlp,
            "event": event["info"],
            "event_uuid": event["uuid"],
            "source_id": r["source_id"],
            "caught": catches.get(event["uuid"], []),
        }
        ip = ips.get(r["value"])
        if ip:
            place, anchor = places.get(ip), ip
        elif r["type"] in HOST_TYPES:
            place, anchor = tld_countries.country_of(_tld(r["type"], r["value"])), r["value"]
        else:
            place = anchor = None
        if place and place["country"]:
            dlat, dlon = _jitter(anchor)
            item.update(country=place["country"], country_name=place["name"],
                        lat=place["lat"] + dlat, lon=place["lon"] + dlon)
        elif ip:
            item["why_not"] = ("not sent to CIRCL at TLP:AMBER" if event_tlp not in ("clear", "green")
                               else "not located yet" if place is None else "no country known")
        elif r["type"] in HOST_TYPES:
            item["why_not"] = "no country in its top-level domain"
        indicators.append(item)

    located = [i for i in indicators if "country" in i]
    countries = Counter((i["country"], i["country_name"]) for i in located)
    used = {i for item in indicators for i in item["caught"]}
    return {
        "days": days,
        "tlp": tlp,
        "exclude_hashes": exclude_hashes,
        "generated_at": time.time(),
        "means": [{"id": k, "label": label, "count": sum(1 for i in indicators if i["means"] == k)}
                  for k, label in MEANS.items()],
        "requirements": {i: names[i] for i in used},
        "indicators": indicators[-_MAX_INDICATORS:],
        "totals": {
            "indicators": len(indicators),
            "caught": sum(1 for i in indicators if i["caught"]),
            "located": len(located),
            "countries": len(countries),
            "litter": len(indicators) - len(located),
        },
        "countries": [{"code": code, "name": name, "count": n} for (code, name), n in countries.most_common(6)],
    }
