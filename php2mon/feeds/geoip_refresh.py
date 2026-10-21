"""Monthly DB-IP lite refresh for the sensor's GeoIP files, plus NULL-row backfill."""
from __future__ import annotations
import asyncio
import gzip
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from php2mon.feeds.base import Collector, Observation
from php2mon.feeds.sources import _setting
from php2mon.sensor.geoip import ASN_FILE, COUNTRY_FILE, GeoLookup

log = logging.getLogger(__name__)

BASE_URL = "https://download.db-ip.com/free/{kind}-{tag}.mmdb.gz"


def month_tag(now: datetime) -> str:
    return f"{now.year:04d}-{now.month:02d}"


def country_url(tag: str) -> str:
    return BASE_URL.format(kind="dbip-country-lite", tag=tag)


def asn_url(tag: str) -> str:
    return BASE_URL.format(kind="dbip-asn-lite", tag=tag)


def _is_current(path: Path, tag: str) -> bool:
    try:
        return month_tag(datetime.fromtimestamp(path.stat().st_mtime, UTC)) == tag
    except OSError:
        return False


def _write_atomic(path: Path, gz_bytes: bytes) -> None:
    data = gzip.decompress(gz_bytes)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


class GeoRefresh(Collector):
    name = "geoip_refresh"
    interval_seconds = 86400

    async def collect(self, ctx) -> list[Observation]:
        directory = _setting(ctx, "geoip_dir")
        if not directory:
            raise RuntimeError("geoip_refresh: GEOIP_DIR not set")
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        now = datetime.now(UTC)
        tag = month_tag(now)
        refreshed = 0
        for fname, url in ((COUNTRY_FILE, country_url(tag)), (ASN_FILE, asn_url(tag))):
            target = directory / fname
            if _is_current(target, tag):
                continue
            resp = await ctx.client.get(url, timeout=120.0, follow_redirects=True)
            if resp.status_code // 100 != 2:
                raise RuntimeError(f"geoip_refresh: {fname} HTTP {resp.status_code}")
            await asyncio.to_thread(_write_atomic, target, resp.content)
            refreshed += 1
        return [Observation(self.name, "geoip_files_refreshed", {}, float(refreshed), now)]


async def backfill(pool, geo: GeoLookup, *, batch: int = 500) -> int:
    """Fill country/ASN on sensor_hits rows where both are NULL. Idempotent.

    Always re-queries from the start: filled rows stop matching. Rows the lookup
    cannot resolve are skipped by id so the loop terminates.
    """
    updated = 0
    last_id = 0
    while True:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id, host(src_ip) AS ip FROM sensor_hits "
                "WHERE country IS NULL AND asn IS NULL AND id > $2 ORDER BY id LIMIT $1",
                batch, last_id)
            if not rows:
                return updated
            for r in rows:
                last_id = r["id"]
                it = SimpleNamespace(src_ip=r["ip"], country=None, asn=None, asn_name=None)
                geo.enrich(it)
                if it.country is None and it.asn is None:
                    continue
                res = await conn.execute(
                    "UPDATE sensor_hits SET country=$1, asn=$2, asn_name=$3 "
                    "WHERE id=$4 AND country IS NULL AND asn IS NULL",
                    it.country, it.asn, it.asn_name, r["id"])
                if res.endswith(" 1"):
                    updated += 1
