import asyncpg
import pytest

from php2mon.db import apply_schema
from php2mon.roles import apply_roles


async def test_roles_have_least_privilege(database_url):
    pool = await asyncpg.create_pool(database_url, min_size=1, max_size=2)
    await apply_schema(pool)
    await apply_roles(pool, sensor_pw="s_pw", collector_pw="c_pw", dashboard_pw="d_pw")
    base = database_url.rsplit("/", 1)[0]
    # dashboard cannot write
    dash = await asyncpg.connect(f"{base}/php2mon", user="php2mon_dashboard", password="d_pw")
    try:
        await dash.fetch("SELECT count(*) FROM sensor_hits")  # allowed
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await dash.execute("INSERT INTO claims (ts, org, claim, url) VALUES (now(), 'x', 'y', 'z')")
    finally:
        await dash.close()
    # sensor cannot read sensor_hits back
    sensor = await asyncpg.connect(f"{base}/php2mon", user="php2mon_sensor", password="s_pw")
    try:
        await sensor.execute(
            "INSERT INTO sensor_hits (ts, src_ip, method, path, body_bytes, multipart_parts, sess_len, resp_status) "
            "VALUES (now(), '203.0.113.1', 'GET', '/', 0, 0, 0, 200)"
        )
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await sensor.fetch("SELECT * FROM sensor_hits")
    finally:
        await sensor.close()
    # applying twice is idempotent
    await apply_roles(pool, sensor_pw="s_pw", collector_pw="c_pw", dashboard_pw="d_pw")
    await pool.close()


async def test_password_with_quotes_is_escaped(database_url):
    pool = await asyncpg.create_pool(database_url, min_size=1, max_size=2)
    await apply_schema(pool)
    pw = "a'b\"c'; DROP TABLE claims; --"
    await apply_roles(pool, sensor_pw=pw, collector_pw="c_pw", dashboard_pw="d_pw")
    base = database_url.rsplit("/", 1)[0]
    conn = await asyncpg.connect(f"{base}/php2mon", user="php2mon_sensor", password=pw)
    await conn.close()
    assert await pool.fetchval("SELECT to_regclass('claims')") is not None
    await pool.close()
