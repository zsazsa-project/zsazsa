"""The indicators marked in a report, so an analyst can look them up.

One set of patterns for both sides: the browser marks the rendered text with
the sources browser_config() hands it, and find() here does the same, so the
tests pin what the page marks. In a report a domain or a URL is marked only
when it is defanged: written plainly there it is nearly always a reference or
the publisher's own site. Nothing inside a URL that is not marked is marked
either, so a hash in a news link stays text. In the analyst's own text, the
preview of a product's Markdown field, a plain one is marked too, written in
lower case as a domain is, and not a file name such as cmd.exe: so not
ASP.NET either.
"""

import ipaddress
import re

from core.vuln_lookup import CVE_RE

# The ways a report writes a dot so that it is not a link.
_DOT = r"(?:\.|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\))"
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"


def _hex(length):
    return rf"(?<!\w)[0-9a-f]{{{length}}}(?!\w)"


# In the order they are tried: a URL first, so what is inside it is spoken for,
# and the longer hashes before the shorter ones.
PATTERNS = [
    ("url", r"\b(?:hxxps?|https?|ftp)(?:\[:\]|:)//[^\s<>\"'`]+"),
    ("cve", CVE_RE.pattern),
    ("sha512", _hex(128)),
    ("sha256", _hex(64)),
    ("sha1", _hex(40)),
    ("md5", _hex(32)),
    ("ip", rf"(?<![\w.]){_OCTET}(?:{_DOT}{_OCTET}){{3}}(?!\w|{_DOT}\d)"),
    ("domain", rf"(?<![\w@./-])(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?{_DOT})+[a-z][a-z0-9-]{{1,23}}(?![\w-]|{_DOT}\w)"),
]
_COMPILED = [(kind, re.compile(source, re.IGNORECASE | re.ASCII)) for kind, source in PATTERNS]
_BY_KIND = dict(_COMPILED)

LABELS = {"url": "URL", "cve": "Vulnerability", "sha512": "SHA-512", "sha256": "SHA-256", "sha1": "SHA-1",
          "md5": "MD5", "ip": "IP address", "domain": "Domain"}

# Addresses that say nothing about an adversary: private, shared, loopback,
# link-local, documentation, benchmarking, multicast and reserved.
NOT_PUBLIC = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
              "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
              "203.0.113.0/24", "224.0.0.0/3"]
_NOT_PUBLIC = [ipaddress.ip_network(n) for n in NOT_PUBLIC]

# What ends a file name rather than a domain, for the analyst's own text, where
# a detection request names cmd.exe and payload.ps1.
FILE_EXTENSIONS = ["exe", "dll", "sys", "ps1", "psm1", "bat", "cmd", "vbs", "js", "jar", "py", "sh", "lnk", "msi",
                   "iso", "img", "zip", "rar", "7z", "gz", "tar", "txt", "log", "pdf", "doc", "docx", "xls", "xlsx",
                   "ppt", "pptx", "rtf", "csv", "json", "xml", "yml", "yaml", "ini", "cfg", "conf", "html", "htm",
                   "php", "asp", "aspx", "jsp", "dat", "bin", "tmp", "db", "md", "png", "jpg", "gif"]

# MISP attribute types whose value can be looked up as it is.
MISP_TYPES = {"ip-src": "ip", "ip-dst": "ip", "domain": "domain", "hostname": "domain", "url": "url",
              "md5": "md5", "sha1": "sha1", "sha256": "sha256", "sha512": "sha512", "vulnerability": "cve"}

_DEFANGED_DOT = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE)
# What closes a sentence or a bracket after a URL, rather than belonging to it.
_URL_TAIL = ".,;:)]"


def refang(value: str) -> str:
    """The value as MISP holds it: dots, the scheme and its colon written back."""
    value = _DEFANGED_DOT.sub(".", value).replace("[:]", ":")
    return re.sub(r"^hxxp", "http", value, flags=re.IGNORECASE)


def _is_public(ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    return not any(address in net for net in _NOT_PUBLIC)


def _plain_domain(value: str) -> bool:
    """Whether a domain written plainly in the analyst's text is one."""
    return value == value.lower() and value.rsplit(".", 1)[1] not in FILE_EXTENSIONS


def find(text: str, plain: bool = False) -> list:
    """The indicators the page marks in this text, as (kind, start, end, value),
    in the order they appear. ``value`` is refanged. With ``plain``, as in the
    analyst's own text, a domain or URL written plainly is one too."""
    taken, found = [], []
    for kind, pattern in _COMPILED:
        for match in pattern.finditer(text):
            raw = match.group(0).rstrip(_URL_TAIL) if kind == "url" else match.group(0)
            start, end = match.start(), match.start() + len(raw)
            if any(start < t_end and end > t_start for t_start, t_end in taken):
                continue
            value = refang(raw)
            if kind == "url":
                taken.append((start, end))
                if value != raw or plain:
                    found.append((kind, start, end, value))
                continue
            if kind == "domain" and value == raw and not (plain and _plain_domain(value)):
                continue
            if kind == "ip" and not _is_public(value):
                continue
            taken.append((start, end))
            found.append((kind, start, end, value.upper() if kind == "cve" else value))
    return sorted(found, key=lambda f: f[1])


def parse(kind: str, value) -> str | None:
    """The value to look up for an indicator of this kind, or None when it is
    not one. It may come defanged; a domain or URL need not be."""
    if kind not in _BY_KIND or not isinstance(value, str) or len(value) > 2048:
        return None
    value = refang(value.strip())
    if not _BY_KIND[kind].fullmatch(value):
        return None
    if kind == "ip" and not _is_public(value):
        return None
    return value.upper() if kind == "cve" else value


def kind_of(misp_type: str, value) -> str | None:
    """The kind a MISP attribute is looked up as, or None when its type is not
    one or its value is not one parse() takes, such as a URL without its scheme."""
    kind = MISP_TYPES.get(misp_type)
    return kind if kind and parse(kind, value) is not None else None


def browser_config() -> dict:
    """What the page needs to mark the same indicators find() does."""
    return {"patterns": [{"kind": kind, "source": source} for kind, source in PATTERNS],
            "notPublic": NOT_PUBLIC, "labels": LABELS, "mispTypes": MISP_TYPES, "fileExtensions": FILE_EXTENSIONS}
