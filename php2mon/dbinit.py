"""One-shot: apply schema and least-privilege roles as the admin user."""

from __future__ import annotations

import asyncio
import os
import sys

import asyncpg

from php2mon.db import apply_schema
from php2mon.roles import apply_roles
from php2mon.claims import load_claims

_PW_VARS = ("SENSOR_DB_PW", "COLLECTOR_DB_PW", "DASHBOARD_DB_PW")


async def _run(dsn: str, pws: dict[str, str]) -> None:
    pool = await asyncpg.create_pool(dsn, min_size=1, max_size=1)
    try:
        await apply_schema(pool)
        await apply_roles(
            pool,
            sensor_pw=pws["SENSOR_DB_PW"],
            collector_pw=pws["COLLECTOR_DB_PW"],
            dashboard_pw=pws["DASHBOARD_DB_PW"],
        )
        # Seed claims here (admin connection) so the dashboard role stays SELECT-only.
        claims_file = os.environ.get("CLAIMS_FILE")
        if claims_file:
            await load_claims(pool, claims_file)
    finally:
        await pool.close()


def main() -> int:
    dsn = os.environ.get("DATABASE_URL", "")
    missing = [v for v in ("DATABASE_URL", *_PW_VARS) if not os.environ.get(v)]
    if missing:
        print(f"dbinit: missing required env: {', '.join(missing)}", file=sys.stderr)
        return 2
    try:
        asyncio.run(_run(dsn, {v: os.environ[v] for v in _PW_VARS}))
    except Exception as exc:
        print(f"dbinit: failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print("dbinit: schema and roles applied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
