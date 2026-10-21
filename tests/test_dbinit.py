import os
import subprocess
import sys

import asyncpg

PWS = {"SENSOR_DB_PW": "s_pw", "COLLECTOR_DB_PW": "c_pw", "DASHBOARD_DB_PW": "d_pw"}


def _run(database_url, **env):
    full = {k: v for k, v in os.environ.items() if k not in PWS}
    full["DATABASE_URL"] = database_url
    full.update(env)
    return subprocess.run(
        [sys.executable, "-m", "php2mon.dbinit"], env=full, capture_output=True, text=True
    )


async def test_dbinit_applies_schema_and_roles_idempotently(database_url):
    for _ in range(2):
        r = _run(database_url, **PWS)
        assert r.returncode == 0, r.stderr
    base = database_url.rsplit("/", 1)[0]
    conn = await asyncpg.connect(f"{base}/php2mon", user="php2mon_collector", password="c_pw")
    try:
        assert await conn.fetchval("SELECT count(*) FROM sensor_hits") >= 0
    finally:
        await conn.close()


def test_dbinit_missing_password_exits_nonzero(database_url):
    r = _run(database_url, SENSOR_DB_PW="x", DASHBOARD_DB_PW="y")
    assert r.returncode != 0
    assert "COLLECTOR_DB_PW" in r.stderr
    assert "SENSOR_DB_PW" not in r.stderr


async def test_dbinit_seeds_claims_idempotently(database_url, tmp_path):
    f = tmp_path / "claims.yaml"
    f.write_text("- {org: Z, claim: c, url: 'https://z', date: 2026-10-21}\n")
    for _ in range(2):
        r = _run(database_url, CLAIMS_FILE=str(f), **PWS)
        assert r.returncode == 0, r.stderr
    conn = await asyncpg.connect(database_url)
    try:
        assert await conn.fetchval("SELECT count(*) FROM claims WHERE org='Z'") == 1
    finally:
        await conn.close()
