"""The asset inventory a vulnerability advisory is checked against.

For now this is a CSV file of "Supplier","Product","Version" rows at
ASSET_INVENTORY_FILE. It is read again once it is older than
ASSET_INVENTORY_REFRESH_MINUTES, so a file another system writes is picked up
without a restart. A later version can ask an external system instead.

A CVE record and an inventory rarely spell a supplier or a product the same
way, so names are compared loosely: case, punctuation and company forms such
as "Inc." do not count, "PAN-OS" is "PANOS", a supplier matches its initials
("Hewlett Packard Enterprise" is "HPE"), a product name may start with its
supplier's ("Apache Log4j" is "Log4j") and a version number run into a word
does not count ("Log4j2" is "Log4j").
"""

import csv
import re
import time
from collections import namedtuple

import config

Asset = namedtuple("Asset", "supplier product version")


class InventoryError(Exception):
    """The asset inventory is switched on but could not be read."""


# Words in a company name that are not the company: "The PHP Group" is PHP.
_COMPANY_FORMS = {"the", "inc", "incorporated", "corp", "corporation", "co", "company", "ltd", "limited", "llc",
                  "plc", "gmbh", "ag", "sa", "bv", "nv", "srl", "oy", "ab", "group", "holdings"}

_cache = {"path": None, "read_at": 0.0, "assets": []}


def enabled() -> bool:
    return bool(getattr(config, "ASSET_INVENTORY_ENABLED", False))


def assets() -> list:
    """The inventory, read again when it is older than the refresh interval."""
    path = getattr(config, "ASSET_INVENTORY_FILE", "data/assets.csv")
    max_age = max(1, int(getattr(config, "ASSET_INVENTORY_REFRESH_MINUTES", 60))) * 60
    if _cache["path"] != path or time.time() - _cache["read_at"] > max_age:
        _cache.update(path=path, read_at=time.time(), assets=read(path))
    return _cache["assets"]


def read(path) -> list:
    """The assets in a CSV file, without a header row if it has one."""
    try:
        # utf-8-sig: a spreadsheet saving as CSV often starts the file with a BOM.
        with open(path, newline="", encoding="utf-8-sig") as handle:
            rows = list(csv.reader(handle, skipinitialspace=True))
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        # An OSError names the path again in its text; its strerror does not.
        raise InventoryError(f"Could not read the asset inventory {path}: "
                             f"{getattr(exc, 'strerror', None) or exc}") from exc
    found = []
    for row in rows:
        supplier, product, version = [value.strip() for value in (row + ["", "", ""])[:3]]
        if product and (supplier.lower(), product.lower()) != ("supplier", "product"):
            found.append(Asset(supplier, product, version))
    return found


def find(vendor: str, product: str):
    """The first asset that is this vendor's product, or None. A vendor or
    supplier left empty matches on the product alone."""
    for asset in assets():
        if vendor and asset.supplier and not _same_supplier(vendor, asset.supplier):
            continue
        if _same_product(_product_words(product, vendor), _product_words(asset.product, asset.supplier)):
            return asset
    return None


def names(name: str, vendor: str, product: str) -> bool:
    """Whether a vendor or product name, such as a focus point, is a CVE
    record's vendor or its product, compared as loosely as the inventory is."""
    return (bool(vendor) and _same_supplier(name, vendor)) or _same_product(_words(name),
                                                                             _product_words(product, vendor))


def _words(name: str) -> list:
    return re.findall(r"[a-z0-9]+", (name or "").lower())


def _supplier_words(name: str) -> list:
    words = _words(name)
    return [w for w in words if w not in _COMPANY_FORMS] or words


def _same_supplier(a: str, b: str) -> bool:
    wa, wb = _supplier_words(a), _supplier_words(b)
    if not wa or not wb:
        return False
    if "".join(wa) == "".join(wb):
        return True
    if len(wa) > 1 and "".join(w[0] for w in wa) == "".join(wb):
        return True
    if len(wb) > 1 and "".join(w[0] for w in wb) == "".join(wa):
        return True
    # One adds a word to the other: "Cisco" and "Cisco Systems".
    shorter, longer = sorted((wa, wb), key=len)
    return longer[:len(shorter)] == shorter


def _product_words(product: str, supplier: str) -> list:
    """The words of a product name without the supplier's it starts with."""
    words = _words(product)
    lead = set(_supplier_words(supplier))
    while len(words) > 1 and words[0] in lead:
        words = words[1:]
    return words


def _same_product(a: list, b: list) -> bool:
    """One product name is the other, or a part of it: "Exchange Server" is in
    "Exchange Server 2019", which "Exchange Server 2016" is not."""
    if not a or not b:
        return False
    # Run together, so "PAN-OS 11" is "PANOS".
    if _same_word("".join(a), "".join(b)):
        return True
    shorter, longer = sorted((a, b), key=len)
    return _contains(longer, shorter)


def _contains(words: list, part: list) -> bool:
    return any(all(_same_word(w, p) for w, p in zip(words[i:i + len(part)], part))
               for i in range(len(words) - len(part) + 1))


def _same_word(a: str, b: str) -> bool:
    """The same word, or one with a version number run into it: "log4j2" is
    "log4j". The number has to follow a letter, so 2019 is not 201."""
    shorter, longer = sorted((a, b), key=len)
    if longer == shorter:
        return True
    return (not shorter[-1].isdigit() and longer.startswith(shorter)
            and longer[len(shorter):].isdigit())
