import asyncpg
from datetime import datetime, timezone

from php2mon.feeds.base import Collector, Observation
from php2mon.feeds.runner import run_once, Context


class OneShot(Collector):
    name = "test"
    interval_seconds = 60
    def __init__(self, obs=None, boom=False):
        super().__init__()
        self._obs = obs or []
        self._boom = boom
    async def collect(self, ctx):
        if self._boom:
            raise RuntimeError("feed down")
        return self._obs


async def test_run_once_inserts_and_is_idempotent(database_url):
    pool = await asyncpg.create_pool(database_url, min_size=1, max_size=2)
    from php2mon.db import apply_schema
    await apply_schema(pool)
    ts = datetime(2026, 10, 21, 15, tzinfo=timezone.utc)
    obs = [Observation("test", "hits", {"loc": "DE", "k": 1}, 5.0, ts)]
    obs2 = [Observation("test", "hits", {"k": 1, "loc": "DE"}, 5.0, ts)]
    ctx = Context(client=None, pool=pool, settings=None)
    await run_once(OneShot(obs), ctx)
    await run_once(OneShot(obs2), ctx)  # second time, different key order, must not duplicate
    async with pool.acquire() as c:
        n = await c.fetchval("SELECT count(*) FROM feed_observations WHERE source='test'")
        v = await c.fetchval("SELECT value FROM feed_observations WHERE source='test'")
        ok = await c.fetchval("SELECT last_ok FROM collector_status WHERE source='test'")
    assert n == 1 and v == 5.0 and ok is not None
    await pool.execute("DELETE FROM feed_observations WHERE source='test'")
    await pool.execute("DELETE FROM collector_status WHERE source='test'")
    await pool.close()


async def test_run_once_records_failure_without_raising(database_url):
    pool = await asyncpg.create_pool(database_url, min_size=1, max_size=2)
    from php2mon.db import apply_schema
    await apply_schema(pool)
    ctx = Context(client=None, pool=pool, settings=None)
    await run_once(OneShot(boom=True), ctx)  # must not raise
    async with pool.acquire() as c:
        row = await c.fetchrow("SELECT last_error, consecutive_failures FROM collector_status WHERE source='test'")
    assert row["consecutive_failures"] == 1 and "feed down" in row["last_error"]
    await pool.execute("DELETE FROM collector_status WHERE source='test'")
    await pool.close()
