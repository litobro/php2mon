"""Country and ASN enrichment from DB-IP lite mmdb files (no key required)."""

from __future__ import annotations

import logging
import os
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
        # (path, mtime) per reader, populated by from_dir; empty for injected readers.
        self._country_src: tuple[Path, float] | None = None
        self._asn_src: tuple[Path, float] | None = None
        self._directory: Path | None = None

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

        geo = cls(open_if_present(COUNTRY_FILE), open_if_present(ASN_FILE))
        geo._directory = Path(directory)
        geo._country_src = cls._stat(Path(directory) / COUNTRY_FILE)
        geo._asn_src = cls._stat(Path(directory) / ASN_FILE)
        return geo

    @staticmethod
    def _stat(path: Path) -> tuple[Path, float] | None:
        try:
            return (path, os.stat(path).st_mtime)
        except OSError:
            return None

    def maybe_reopen(self) -> bool:
        """Re-open readers whose mmdb file changed on disk. Returns True if any swapped."""
        if self._directory is None:
            return False
        changed = False
        for name, attr, src_attr in ((COUNTRY_FILE, "_country", "_country_src"),
                                     (ASN_FILE, "_asn", "_asn_src")):
            path = self._directory / name
            new = self._stat(path)
            if new is None or new == getattr(self, src_attr):
                continue
            try:
                reader = maxminddb.open_database(str(path))
            except Exception as exc:
                log.warning("geoip reopen of %s failed; keeping previous reader: %s", path, exc)
                continue
            old = getattr(self, attr)
            setattr(self, attr, reader)
            setattr(self, src_attr, new)
            changed = True
            if old is not None and hasattr(old, "close"):
                try:
                    old.close()
                except Exception:
                    pass
        return changed

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
