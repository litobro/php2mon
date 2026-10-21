"""Run a collector once: collect, upsert observations, record status."""
from __future__ import annotations
import json as _json
import logging
from dataclasses import dataclass

from apscheduler.schedulers.asyncio import AsyncIOScheduler

log = logging.getLogger(__name__)

UPSERT = """
INSERT INTO feed_observations (ts, source, metric, dimensions, value)
VALUES ($1, $2, $3, $4::jsonb, $5)
ON CONFLICT (source, metric, md5(dimensions::text), ts)
DO UPDATE SET value = EXCLUDED.value
"""


@dataclass
class Context:
    client: object
    pool: object
    settings: object


async def run_once(collector, ctx) -> None:
    try:
        observations = await collector.collect(ctx)
    except Exception as exc:
        collector.consecutive_failures += 1
        log.warning("collector %s failed: %s", collector.name, exc)
        async with ctx.pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO collector_status (source, last_error, consecutive_failures)
                   VALUES ($1, $2, $3)
                   ON CONFLICT (source) DO UPDATE SET last_error=$2,
                     consecutive_failures=collector_status.consecutive_failures+1""",
                collector.name, f"{type(exc).__name__}: {exc}", collector.consecutive_failures,
            )
        return
    async with ctx.pool.acquire() as conn:
        async with conn.transaction():
            for o in observations:
                await conn.execute(UPSERT, o.ts, o.source, o.metric, _json.dumps(o.dimensions, sort_keys=True), o.value)
            await conn.execute(
                """INSERT INTO collector_status (source, last_ok, consecutive_failures)
                   VALUES ($1, now(), 0)
                   ON CONFLICT (source) DO UPDATE SET last_ok=now(), consecutive_failures=0, last_error=NULL""",
                collector.name,
            )
    collector.consecutive_failures = 0


def build_scheduler(collectors, ctx) -> AsyncIOScheduler:
    sched = AsyncIOScheduler()
    for c in collectors:
        sched.add_job(run_once, "interval", seconds=c.interval_seconds, args=[c, ctx],
                      id=c.name, max_instances=1, coalesce=True, next_run_time=None)
    return sched
