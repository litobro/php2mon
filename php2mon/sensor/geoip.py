"""Country and ASN enrichment from DB-IP lite mmdb files (no key required)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Protocol

import maxminddb

from php2mon.sensor.hits import HitRecord

log = logging.getLogger(__name__)

COUNTRY_FILE = "dbip-country-lite.mmdb"
ASN_FILE = "dbip-asn-lite.mmdb"


class Reader(Protocol):
    def get(self, ip: str) -> dict[str, Any] | None: ...


class GeoLookup:
    def __init__(self, country_reader: Reader | None = None, asn_reader: Reader | None = None) -> None:
        self._country = country_reader
        self._asn = asn_reader

    @classmethod
    def from_dir(cls, directory: Path) -> "GeoLookup":
        def open_if_present(name: str) -> Reader | None:
            path = Path(directory) / name
            if not path.exists():
                log.warning("geoip file %s not found; enrichment disabled for it", path)
                return None
            try:
                return maxminddb.open_database(str(path))
            except Exception as exc:
                log.warning("geoip file %s unreadable; enrichment disabled for it: %s", path, exc)
                return None

        return cls(open_if_present(COUNTRY_FILE), open_if_present(ASN_FILE))

    def enrich(self, hit: HitRecord) -> None:
        try:
            if self._country is not None:
                rec = self._country.get(hit.src_ip) or {}
                hit.country = (rec.get("country") or {}).get("iso_code")
            if self._asn is not None:
                rec = self._asn.get(hit.src_ip) or {}
                hit.asn = rec.get("autonomous_system_number")
                hit.asn_name = rec.get("autonomous_system_organization")
        except Exception as exc:
            log.debug("geoip lookup failed for %s: %s", hit.src_ip, exc)
