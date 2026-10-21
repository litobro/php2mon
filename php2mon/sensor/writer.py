"""Buffered, fault-tolerant writer of HitRecords into Postgres."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from collections import deque
from typing import Protocol

import asyncpg

from php2mon.db import apply_schema
from php2mon.sensor.hits import HitRecord

log = logging.getLogger(__name__)

INSERT_SQL = """
INSERT INTO sensor_hits (
    ts, src_ip, country, asn, asn_name, method, path, host, user_agent,
    content_type, body_bytes, multipart_parts, sess_len, resp_status,
    signatures, detail
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16::jsonb)
"""


class HitSink(Protocol):
    async def put(self, hit: HitRecord) -> None: ...


class MemorySink:
    def __init__(self) -> None:
        self.hits: list[HitRecord] = []

    async def put(self, hit: HitRecord) -> None:
        self.hits.append(hit)


def hit_row(hit: HitRecord) -> tuple:
    return (
        hit.ts,
        ipaddress.ip_address(hit.src_ip),
        hit.country,
        hit.asn,
        hit.asn_name,
        hit.method,
        hit.path[:2048],
        hit.host,
        hit.user_agent,
        hit.content_type,
        hit.body_bytes,
        hit.multipart_parts,
        hit.sess_len,
        hit.resp_status,
        list(hit.signatures),
        json.dumps(hit.to_detail()) if hit.detail_kept else None,
    )


class PostgresWriter:
    def __init__(
        self,
        dsn: str,
        *,
        batch_size: int = 500,
        flush_interval: float = 1.0,
        max_buffer: int = 10_000,
    ) -> None:
        self._dsn = dsn
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._max_buffer = max_buffer
        self._buffer: deque[tuple] = deque()
        self._pool: asyncpg.Pool | None = None
        self._task: asyncio.Task | None = None
        self.dropped = 0

    async def put(self, hit: HitRecord) -> None:
        if len(self._buffer) >= self._max_buffer:
            self._buffer.popleft()
            self.dropped += 1
        self._buffer.append(hit_row(hit))

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self.flush()
        if self._pool is not None:
            await self._pool.close()

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self._flush_interval)
            await self.flush()

    async def flush(self) -> bool:
        while self._buffer:
            rows = [self._buffer.popleft() for _ in range(min(self._batch_size, len(self._buffer)))]
            try:
                await self._insert(rows)
            except Exception as exc:
                self._buffer.extendleft(reversed(rows))
                log.warning("insert failed, %d rows buffered: %s", len(self._buffer), exc)
                return False
        return True

    async def _insert(self, rows: list[tuple]) -> None:
        if self._pool is None:
            self._pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=2)
            await apply_schema(self._pool)
        async with self._pool.acquire() as conn:
            await conn.executemany(INSERT_SQL, rows)
