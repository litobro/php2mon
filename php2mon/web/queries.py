"""Read-only, parameterized SELECTs for the dashboard.

Every function takes an asyncpg pool and only issues SELECTs; the dashboard
role has no write privileges.
"""

from __future__ import annotations

from datetime import datetime

# Signatures that indicate exploit-confidence traffic (confidence exploit/likely).
EXPLOIT_SIGNATURES = ["mp-large", "mp-large-repeat", "oom-repeat", "sess-repeat"]

WINDOWS = {"24h": 24, "7d": 168, "30d": 720}
DEFAULT_WINDOW_HOURS = 24

# Collector intervals in seconds (mirrors php2mon.feeds.sources; the dashboard
# image does not ship the collector extra).
COLLECTOR_INTERVALS = {"isc": 3600, "radar": 3600, "kev": 1800, "shodan": 86400}
DEFAULT_INTERVAL = 3600
STALE_FACTOR = 3


def window_hours(raw: str | None) -> int:
    """Whitelist-clamp a user-supplied window; anything unknown yields 24."""
    return WINDOWS.get(raw or "", DEFAULT_WINDOW_HOURS)


async def headline(pool, patch_release: datetime) -> dict:
    async with pool.acquire() as c:
        row = await c.fetchrow(
            """SELECT
                 count(*) FILTER (WHERE signatures && $1::text[]
                                  AND ts >= date_trunc('hour', now())) AS cur_hour,
                 count(*) FILTER (WHERE ts >= now() - interval '24 hours') AS total_24h,
                 count(*) FILTER (WHERE signatures && $1::text[] AND ts >= $2) AS since_patch,
                 count(*) FILTER (WHERE signatures && $1::text[]
                                  AND ts >= $2 - interval '24 hours' AND ts < $2) AS pre_patch,
                 count(DISTINCT src_ip) FILTER (WHERE ts >= now() - interval '24 hours') AS ips_24h
               FROM sensor_hits
               WHERE ts >= LEAST($2::timestamptz - interval '24 hours', now() - interval '24 hours')""",
            EXPLOIT_SIGNATURES, patch_release,
        )
        l7 = await c.fetchval(
            """SELECT value FROM feed_observations
               WHERE source='radar' AND metric='l7_attacks' ORDER BY ts DESC LIMIT 1"""
        )
    return {
        "current_hour_exploit_hits": row["cur_hour"],
        "total_hits_24h": row["total_24h"],
        "unique_ips_24h": row["ips_24h"],
        "exploit_hits_since_patch": row["since_patch"],
        "pre_patch_exploit_hits": row["pre_patch"],
        "l7_attacks_latest": l7,
    }


async def timeline(pool, hours: int) -> dict:
    async with pool.acquire() as c:
        hits = await c.fetch(
            """SELECT date_trunc('hour', ts) AS t,
                      count(*) AS total,
                      count(*) FILTER (WHERE signatures && $1::text[]) AS exploit
               FROM sensor_hits WHERE ts >= now() - make_interval(hours => $2)
               GROUP BY 1 ORDER BY 1""",
            EXPLOIT_SIGNATURES, hours,
        )
        radar = await c.fetch(
            """SELECT ts, value FROM feed_observations
               WHERE source='radar' AND metric='l7_attacks'
                 AND ts >= now() - make_interval(hours => $1) ORDER BY ts""",
            hours,
        )
        kev = await c.fetch(
            """SELECT dimensions->>'cve' AS cve, min(ts) AS first_seen
               FROM feed_observations
               WHERE source='kev' AND metric='kev_listed' AND value > 0
               GROUP BY 1 ORDER BY 2"""
        )
        kev_added = await c.fetch(
            """SELECT DISTINCT ON (dimensions->>'cve') dimensions->>'cve' AS cve, value
               FROM feed_observations
               WHERE source='kev' AND metric='kev_date_added_epoch'
               ORDER BY dimensions->>'cve', ts DESC"""
        )
    added = {r["cve"]: r["value"] for r in kev_added}
    return {
        "hits": [{"t": r["t"].isoformat(), "total": r["total"], "exploit": r["exploit"]} for r in hits],
        "radar": [{"t": r["ts"].isoformat(), "value": r["value"]} for r in radar],
        "kev": [
            {"cve": r["cve"], "first_seen": r["first_seen"].isoformat(),
             "date_added_epoch": added.get(r["cve"])}
            for r in kev
        ],
    }


async def sources(pool, hours: int, limit: int = 25) -> list[dict]:
    async with pool.acquire() as c:
        rows = await c.fetch(
            """SELECT country, asn, max(asn_name) AS asn_name,
                      count(*) AS hits,
                      count(*) FILTER (WHERE signatures && $1::text[]) AS exploit_hits
               FROM sensor_hits WHERE ts >= now() - make_interval(hours => $2)
               GROUP BY country, asn
               ORDER BY exploit_hits DESC, hits DESC LIMIT $3""",
            EXPLOIT_SIGNATURES, hours, limit,
        )
    return [dict(r) for r in rows]


async def adoption(pool) -> list[dict]:
    async with pool.acquire() as c:
        rows = await c.fetch(
            """SELECT ts,
                      max(value) FILTER (WHERE metric='php_hosts_fixed') AS fixed,
                      max(value) FILTER (WHERE metric='php_hosts_vulnerable') AS vulnerable
               FROM feed_observations
               WHERE source='shodan' AND metric IN ('php_hosts_fixed','php_hosts_vulnerable')
               GROUP BY ts ORDER BY ts"""
        )
    return [{"t": r["ts"].isoformat(), "fixed": r["fixed"], "vulnerable": r["vulnerable"]} for r in rows]


async def claims(pool) -> list[dict]:
    async with pool.acquire() as c:
        rows = await c.fetch("SELECT ts, org, claim, url FROM claims ORDER BY ts DESC, id DESC")
    return [{"ts": r["ts"].isoformat(), "org": r["org"], "claim": r["claim"], "url": r["url"]} for r in rows]


async def status(pool) -> list[dict]:
    async with pool.acquire() as c:
        rows = await c.fetch(
            """SELECT source, last_ok, last_error, consecutive_failures,
                      now() AS db_now FROM collector_status ORDER BY source"""
        )
    out = []
    for r in rows:
        interval = COLLECTOR_INTERVALS.get(r["source"], DEFAULT_INTERVAL)
        last_ok = r["last_ok"]
        stale = last_ok is None or (r["db_now"] - last_ok).total_seconds() > STALE_FACTOR * interval
        out.append({
            "source": r["source"],
            "last_ok": last_ok.isoformat() if last_ok else None,
            "last_error": r["last_error"],
            "consecutive_failures": r["consecutive_failures"],
            "stale": stale,
        })
    return out
