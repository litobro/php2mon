from datetime import datetime, timedelta, timezone
from pathlib import Path

import asyncpg
import pytest
from fastapi.testclient import TestClient

from php2mon.db import apply_schema
from php2mon.web import app as webapp
from php2mon.web.app import create_app, load_claims

NOW = datetime.now(timezone.utc)


@pytest.fixture
async def seeded(database_url):
    pool = await asyncpg.create_pool(database_url, min_size=1, max_size=2)
    await apply_schema(pool)
    async with pool.acquire() as c:
        await c.execute(
            "TRUNCATE sensor_hits, feed_observations, collector_status, claims RESTART IDENTITY"
        )

        # Anchor hit timestamps to the DB clock (now()) rather than an
        # import-time constant, so the "current hour" assertions can't
        # straddle the hour boundary when CI runs a few minutes past :00.
        async def hit(ago, cc, asn, sigs):
            # asyncpg encodes a timedelta as an interval; subtract from the DB
            # clock so timestamps are anchored to now(), not an import-time value.
            await c.execute(
                """INSERT INTO sensor_hits (ts, src_ip, country, asn, asn_name, method, path,
                   body_bytes, multipart_parts, sess_len, resp_status, signatures)
                   VALUES (now() - $1::interval,'203.0.113.9',$2,$3,'AS-X','POST','/x',0,0,0,200,$4)""",
                ago, cc, asn, sigs,
            )

        # Three "recent" hits near now() (always in the current clock hour and
        # within 24h); one 3 days old for the pre/post-patch delta tests.
        await hit(timedelta(seconds=0), "US", 64500, ["mp-large"])
        await hit(timedelta(seconds=1), "US", 64500, ["oom-repeat", "scan"])
        await hit(timedelta(seconds=2), "DE", 64501, ["scan"])
        await hit(timedelta(days=3), "CN", 64502, ["sess-repeat"])
        for metric, v, d in (
            ("php_hosts_fixed", 10, "{}"), ("php_hosts_vulnerable", 90, "{}"),
            ("l7_attacks", 5, "{}"), ("kev_listed", 1, '{"cve":"CVE-2026-0001"}'),
            ("kev_date_added_epoch", NOW.timestamp(), '{"cve":"CVE-2026-0001"}'),
        ):
            src = "shodan" if metric.startswith("php") else "radar" if metric == "l7_attacks" else "kev"
            await c.execute(
                "INSERT INTO feed_observations (ts, source, metric, dimensions, value) "
                "VALUES ($1,$2,$3,$4::jsonb,$5)", NOW, src, metric, d, float(v),
            )
        await c.execute(
            "INSERT INTO collector_status (source, last_ok) VALUES ('isc',$1),('kev',$2)",
            NOW, NOW - timedelta(days=2),
        )
        await c.execute(
            "INSERT INTO claims (ts, org, claim, url) VALUES ($1,'Acme','claim text','https://e.x')",
            NOW,
        )
    yield pool
    await pool.close()


@pytest.fixture
def client(seeded, database_url):
    with TestClient(create_app(database_url)) as c:
        yield c


def test_headline(client):
    j = client.get("/api/headline").json()
    assert j["patch_release"].startswith("2026-10-21T14:00")
    assert j["current_hour_exploit_hits"] == 2
    assert j["total_hits_24h"] == 3


def test_headline_delta_logic(seeded, database_url):
    # release 1h ago: the 2 recent exploit hits count, the 3-day-old one is pre-patch
    rel = NOW - timedelta(hours=1)
    with TestClient(create_app(database_url, patch_release=rel)) as c:
        j = c.get("/api/headline").json()
    assert j["exploit_hits_since_patch"] == 2
    assert j["pre_patch_exploit_hits"] == 0  # 24h before release has none
    rel = NOW - timedelta(days=4)
    with TestClient(create_app(database_url, patch_release=rel)) as c:
        j = c.get("/api/headline").json()
    assert j["exploit_hits_since_patch"] == 3


def test_timeline_shape(client):
    j = client.get("/api/timeline?window=24h").json()
    assert j["window_hours"] == 24
    assert sum(p["exploit"] for p in j["hits"]) == 2
    assert sum(p["total"] for p in j["hits"]) == 3
    assert "annotations" in j and j["annotations"]["patch_release"]
    assert any(k["cve"] == "CVE-2026-0001" for k in j["annotations"]["kev"])
    assert j["radar"]


def test_window_7d_includes_older(client):
    j = client.get("/api/timeline?window=7d").json()
    assert j["window_hours"] == 168
    assert sum(p["total"] for p in j["hits"]) == 4


def test_window_param_is_clamped(client):
    for bad in ("", "nonsense", "9999999d", "-5", "0", "999999999999999999999", "24h; DROP TABLE x"):
        for ep in ("timeline", "sources", "iocs"):
            r = client.get(f"/api/{ep}", params={"window": bad})
            assert r.status_code == 200, (ep, bad)
            assert r.json()["window_hours"] == 24
    assert client.get("/api/timeline").json()["window_hours"] == 24
    assert client.get("/api/sources?window=30d").json()["window_hours"] == 720


def test_sources(client):
    j = client.get("/api/sources?window=24h").json()
    rows = {(r["country"], r["asn"]): r for r in j["rows"]}
    assert rows[("US", 64500)]["hits"] == 2
    assert rows[("US", 64500)]["exploit_hits"] == 2
    assert rows[("DE", 64501)]["exploit_hits"] == 0
    assert ("CN", 64502) not in rows


def test_iocs_surfaces_exploit_source_ips(client):
    j = client.get("/api/iocs?window=24h").json()
    assert j["window_hours"] == 24
    # Only the IP with exploit-signature hits appears; the fixture's recent
    # hits (mp-large, oom-repeat) share one src_ip, the DE scan-only hit does not qualify it separately.
    assert len(j["iocs"]) == 1
    ioc = j["iocs"][0]
    assert ioc["ip"] == "203.0.113.9"
    assert ioc["exploit_hits"] == 2          # mp-large + oom-repeat, within 24h
    assert ioc["total_hits"] == 3            # all three recent hits from this IP
    assert set(ioc["signatures"]) == {"mp-large", "oom-repeat"}
    assert ioc["first_seen"] and ioc["last_seen"]


def test_iocs_window_includes_older_signature(client):
    j = client.get("/api/iocs?window=7d").json()
    ioc = next(r for r in j["iocs"] if r["ip"] == "203.0.113.9")
    # the 3-day-old sess-repeat hit now falls in-window
    assert ioc["exploit_hits"] == 3
    assert "sess-repeat" in ioc["signatures"]


def test_adoption(client):
    j = client.get("/api/adoption").json()
    assert j["series"][-1]["fixed"] == 10
    assert j["series"][-1]["vulnerable"] == 90


def test_claims(client):
    j = client.get("/api/claims").json()
    assert j["claims"][0]["org"] == "Acme"


def test_status_flags_stale(client):
    j = {s["source"]: s for s in client.get("/api/status").json()["collectors"]}
    assert j["isc"]["stale"] is False
    assert j["kev"]["stale"] is True


def test_index_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "php2mon" in r.text
    assert client.get("/static/chart.umd.min.js").status_code == 200


def test_index_only_local_assets():
    import re
    html = (Path(webapp.__file__).parent / "static" / "index.html").read_text()
    urls = re.findall(r'(?:src|href)="(https?://[^"]+)"', html)
    assert all(u.startswith("https://db-ip.com") or "creativecommons.org" in u
               or "sans.edu" in u or "radar.cloudflare.com" in u for u in urls)
    assert not re.findall(r"<(?:script|link)[^>]+(?:src|href)=\"https?://", html)
    assert "CC BY 4.0" in html and "CC BY-NC-SA 4.0" in html and "CC BY-NC 4.0" in html


async def test_load_claims_idempotent(seeded, tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("- {org: A, claim: one, url: 'https://a', date: 2026-10-20}\n"
                 "- {org: B, claim: two, url: 'https://b', date: 2026-10-21}\n")
    await load_claims(seeded, p)
    await load_claims(seeded, p)
    async with seeded.acquire() as c:
        assert await c.fetchval("SELECT count(*) FROM claims") == 2
        assert await c.fetchval("SELECT count(*) FROM claims WHERE org='Acme'") == 0


def test_dashboard_has_no_write_routes(client):
    for route in client.app.routes:
        assert getattr(route, "methods", {"GET"}) <= {"GET", "HEAD"}
