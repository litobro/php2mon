import asyncio
import gzip
import os
from datetime import UTC, datetime
from types import SimpleNamespace

import asyncpg
import pytest

from php2mon.feeds import geoip_refresh
from php2mon.feeds.geoip_refresh import GeoRefresh, asn_url, backfill, country_url, month_tag
from php2mon.sensor import geoip
from php2mon.sensor.geoip import ASN_FILE, COUNTRY_FILE, GeoLookup


def test_month_tag_and_url():
    assert month_tag(datetime(2026, 10, 1, tzinfo=UTC)) == "2026-10"
    assert country_url("2026-10") == "https://download.db-ip.com/free/dbip-country-lite-2026-10.mmdb.gz"
    assert asn_url("2026-10") == "https://download.db-ip.com/free/dbip-asn-lite-2026-10.mmdb.gz"


class FakeGeo(GeoLookup):
    def __init__(self, mapping):
        super().__init__()
        self._m = mapping

    def enrich(self, hit):
        v = self._m.get(hit.src_ip)
        if v:
            hit.country, hit.asn, hit.asn_name = v


async def test_backfill_fills_null_rows_only(database_url):
    pool = await asyncpg.create_pool(database_url, min_size=1, max_size=2)
    from php2mon.db import apply_schema
    await apply_schema(pool)
    async with pool.acquire() as c:
        await c.execute("DELETE FROM sensor_hits")
        for ip in ("203.0.113.1", "203.0.113.2", "203.0.113.3"):
            await c.execute("INSERT INTO sensor_hits (ts, src_ip, method, path, body_bytes, multipart_parts, sess_len, resp_status) VALUES (now(),$1,'GET','/',0,0,0,200)", ip)
        await c.execute("UPDATE sensor_hits SET country='US' WHERE src_ip='203.0.113.2'")
    geo = FakeGeo({"203.0.113.1": ("DE", 64500, "EX")})
    n = await backfill(pool, geo, batch=1)  # 113.3 is unresolvable; must not loop forever
    assert n == 1
    n2 = await backfill(pool, geo, batch=10)
    assert n2 == 0
    async with pool.acquire() as c:
        r = await c.fetchrow("SELECT country, asn FROM sensor_hits WHERE src_ip='203.0.113.1'")
    assert r["country"] == "DE" and r["asn"] == 64500
    await pool.execute("DELETE FROM sensor_hits")
    await pool.close()


class _Reader:
    def __init__(self, path):
        self.path = path
        self.closed = False

    def get(self, ip):
        return None

    def close(self):
        self.closed = True


def test_maybe_reopen_swaps_reader_on_mtime_change(tmp_path, monkeypatch):
    monkeypatch.setattr(geoip.maxminddb, "open_database", lambda p: _Reader(p))
    c, a = tmp_path / COUNTRY_FILE, tmp_path / ASN_FILE
    c.write_bytes(b"x")
    a.write_bytes(b"x")
    geo = GeoLookup.from_dir(tmp_path)
    first = geo._country
    assert geo.maybe_reopen() is False and geo._country is first
    os.utime(c, (1, 1))
    assert geo.maybe_reopen() is True
    assert geo._country is not first and first.closed
    assert geo.maybe_reopen() is False


def test_maybe_reopen_noop_for_injected_readers():
    assert GeoLookup(object(), object()).maybe_reopen() is False


class _Resp:
    status_code = 200

    def __init__(self, content):
        self.content = content


class _Client:
    def __init__(self):
        self.urls = []

    async def get(self, url, **kw):
        self.urls.append(url)
        return _Resp(gzip.compress(b"MMDB:" + url.encode()))


async def test_georefresh_downloads_then_skips(tmp_path):
    ctx = SimpleNamespace(settings=SimpleNamespace(geoip_dir=str(tmp_path)), client=_Client())
    obs = await GeoRefresh().collect(ctx)
    assert obs[0].value == 2 and len(ctx.client.urls) == 2
    assert (tmp_path / COUNTRY_FILE).read_bytes().startswith(b"MMDB:")
    assert not list(tmp_path.glob("*.tmp"))
    obs = await GeoRefresh().collect(ctx)
    assert obs[0].value == 0 and len(ctx.client.urls) == 2
