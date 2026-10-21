"""Run the feed collectors: python -m php2mon.feeds"""
from __future__ import annotations
import asyncio
import logging
import os
from pathlib import Path

import asyncpg
import httpx

from php2mon.feeds.geoip_refresh import GeoRefresh, backfill
from php2mon.feeds.runner import Context, build_scheduler, run_once
from php2mon.feeds.settings import Settings
from php2mon.feeds.sources import CisaKev, CloudflareRadar, IscWebHoneypot, ShodanExposure
from php2mon.sensor.geoip import GeoLookup

log = logging.getLogger(__name__)


def build_collectors(settings: Settings) -> list:
    collectors = [IscWebHoneypot(), CisaKev(), GeoRefresh()]
    if settings.cf_radar_token:
        collectors.append(CloudflareRadar())
    if settings.shodan_api_key:
        collectors.append(ShodanExposure())
    return collectors


async def amain(settings: Settings) -> None:
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=4)
    async with httpx.AsyncClient() as client:
        ctx = Context(client, pool, settings)
        collectors = build_collectors(settings)
        for c in collectors:
            await run_once(c, ctx)
            if isinstance(c, GeoRefresh) and c.consecutive_failures == 0:
                try:
                    n = await backfill(pool, GeoLookup.from_dir(Path(settings.geoip_dir)))
                    log.info("geoip backfill updated %d rows", n)
                except Exception:
                    log.exception("geoip backfill failed")
        sched = build_scheduler(collectors, ctx)
        sched.start()
        await asyncio.Event().wait()


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    asyncio.run(amain(Settings.from_env()))


if __name__ == "__main__":
    main()
