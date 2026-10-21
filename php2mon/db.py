"""Database helpers shared by sensor, collector, and dashboard."""

from __future__ import annotations

from pathlib import Path

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


async def apply_schema(pool) -> None:
    async with pool.acquire() as conn:
        await conn.execute(SCHEMA_PATH.read_text())
