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

class WriterSetupError(Exception):
    """Pool creation or schema application failed; the rows themselves are fine."""


TRANSIENT_ERRORS = (
    WriterSetupError,
    OSError,
    asyncio.TimeoutError,
    asyncpg.PostgresConnectionError,
    asyncpg.InterfaceError,
    asyncpg.exceptions.OperatorInterventionError,
    asyncpg.exceptions.InsufficientResourcesError,
)

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


def _clean(s: str | None) -> str | None:
    return s.replace("\x00", "") if isinstance(s, str) else None


def _deep_clean(obj):
    if isinstance(obj, str):
        return obj.replace("\x00", "")
    if isinstance(obj, dict):
        return {_deep_clean(k): _deep_clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_deep_clean(v) for v in obj]
    return obj


def hit_row(hit: HitRecord) -> tuple:
    return (
        hit.ts,
        ipaddress.ip_address(hit.src_ip),
        hit.country,
        hit.asn,
        _clean(hit.asn_name),
        _clean(hit.method),
        _clean(hit.path)[:2048],
        _clean(hit.host),
        _clean(hit.user_agent),
        _clean(hit.content_type),
        hit.body_bytes,
        hit.multipart_parts,
        hit.sess_len,
        hit.resp_status,
        [_clean(sig) for sig in hit.signatures],
        json.dumps(_deep_clean(hit.to_detail())) if hit.detail_kept else None,
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
        self._consecutive_failures = 0
        self._last_put_error = ""
        self.dropped = 0
        self.rejected = 0

    async def put(self, hit: HitRecord) -> None:
        try:
            row = hit_row(hit)
        except Exception as exc:
            self.rejected += 1
            msg = str(exc)
            if msg != self._last_put_error:
                self._last_put_error = msg
                log.warning("rejected unrecordable hit: %s", msg)
            return
        if len(self._buffer) >= self._max_buffer:
            self._buffer.popleft()
            self.dropped += 1
        self._buffer.append(row)

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        try:
            await self._ensure_pool()
        except Exception as exc:
            log.warning("database not ready at startup, will retry: %s", exc)
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if not await self.flush() and self._buffer:
            log.error("shutting down with %d buffered rows lost", len(self._buffer))
        if self._pool is not None:
            await self._pool.close()

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self._flush_interval)
            await self.flush()

    def _note_failure(self, exc: BaseException) -> None:
        self._consecutive_failures += 1
        n = self._consecutive_failures
        if n == 1 or n % 60 == 0:
            log.warning("insert failed (%d consecutive), %d rows buffered: %s", n, len(self._buffer), exc)

    async def flush(self) -> bool:
        while self._buffer:
            rows = [self._buffer.popleft() for _ in range(min(self._batch_size, len(self._buffer)))]
            try:
                await self._insert(rows)
            except Exception as exc:
                if isinstance(exc, TRANSIENT_ERRORS):
                    self._buffer.extendleft(reversed(rows))
                    self._note_failure(exc)
                    return False
                if not await self._insert_singly(rows):
                    return False
                self._note_success()
                continue
            except BaseException:
                self._buffer.extendleft(reversed(rows))
                raise
            self._note_success()
        return True

    def _note_success(self) -> None:
        if self._consecutive_failures:
            log.info("database writes recovered after %d failures", self._consecutive_failures)
            self._consecutive_failures = 0

    async def _insert_singly(self, rows: list[tuple]) -> bool:
        for i, row in enumerate(rows):
            try:
                await self._insert([row])
            except Exception as exc:
                if isinstance(exc, TRANSIENT_ERRORS):
                    self._buffer.extendleft(reversed(rows[i:]))
                    self._note_failure(exc)
                    return False
                if row[15] is not None:
                    try:
                        await self._insert([row[:15] + (None,)])
                    except Exception as exc2:
                        if isinstance(exc2, TRANSIENT_ERRORS):
                            self._buffer.extendleft(reversed(rows[i:]))
                            self._note_failure(exc2)
                            return False
                        exc = exc2
                    except BaseException:
                        self._buffer.extendleft(reversed(rows[i:]))
                        raise
                    else:
                        log.warning("stored hit without detail (path=%r): %s", row[6], exc)
                        continue
                self.rejected += 1
                log.warning("rejected row (path=%r): %s", row[6], exc)
            except BaseException:
                self._buffer.extendleft(reversed(rows[i:]))
                raise
        return True

    async def _ensure_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            try:
                pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=2)
                try:
                    await apply_schema(pool)
                except BaseException:
                    await pool.close()
                    raise
            except Exception as exc:
                raise WriterSetupError(str(exc)) from exc
            self._pool = pool
        return self._pool

    async def _insert(self, rows: list[tuple]) -> None:
        pool = await self._ensure_pool()
        async with pool.acquire() as conn:
            await conn.executemany(INSERT_SQL, rows)
