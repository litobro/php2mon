"""Seed the claims table from the hand-edited claims.yaml (admin/startup step)."""

from __future__ import annotations

from datetime import date, datetime, time, timezone
from pathlib import Path

import yaml


def _ts(value) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime.combine(value, time(), tzinfo=timezone.utc)
    return datetime.fromisoformat(str(value)).replace(tzinfo=timezone.utc)


async def load_claims(pool, path) -> int:
    """Replace the claims table with the rows in the YAML file (idempotent).

    Needs write rights: call it from the admin/startup step, not the dashboard.
    """
    rows = yaml.safe_load(Path(path).read_text()) or []
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("DELETE FROM claims")
            await conn.executemany(
                "INSERT INTO claims (ts, org, claim, url) VALUES ($1, $2, $3, $4)",
                [(_ts(r["date"]), r["org"], r["claim"], r.get("url")) for r in rows],
            )
    return len(rows)
