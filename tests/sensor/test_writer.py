import asyncio
import json
import logging

import asyncpg
import pytest

from php2mon.sensor.hits import build_hit
from php2mon.sensor.writer import MemorySink, PostgresWriter, WriterSetupError, hit_row


def _hit(path="/", ip="203.0.113.1"):
    h = build_hit(src_ip=ip, method="GET", path=path, headers=[("Host", "x")], body_bytes=0, multipart_parts=0, body_head=b"hi")
    h.resp_status = 200
    h.signatures = ["php-probe"]
    return h


class RecordingWriter(PostgresWriter):
    def __init__(self, fail_times=0, **kw):
        super().__init__("postgresql://unused", **kw)
        self.inserted = []
        self.fail_times = fail_times

    async def _insert(self, rows):
        if self.fail_times:
            self.fail_times -= 1
            raise ConnectionError("db down")
        self.inserted.extend(rows)


async def test_memory_sink_collects():
    sink = MemorySink()
    await sink.put(_hit())
    assert len(sink.hits) == 1


async def test_flush_retries_rows_after_failure():
    w = RecordingWriter(fail_times=1)
    for p in ("/a", "/b", "/c"):
        await w.put(_hit(p))
    assert await w.flush() is False
    assert w.inserted == []
    assert await w.flush() is True
    assert [r[6] for r in w.inserted] == ["/a", "/b", "/c"]
    assert await w.flush() is True  # empty buffer is fine


async def test_buffer_cap_drops_oldest():
    w = RecordingWriter(max_buffer=5)
    for i in range(7):
        await w.put(_hit(f"/{i}"))
    assert w.dropped == 2
    await w.flush()
    assert [r[6] for r in w.inserted] == ["/2", "/3", "/4", "/5", "/6"]


async def test_flush_drains_multiple_batches():
    w = RecordingWriter(batch_size=2)
    for i in range(5):
        await w.put(_hit(f"/{i}"))
    assert await w.flush() is True
    assert len(w.inserted) == 5


def test_hit_row_shape():
    row = hit_row(_hit())
    assert len(row) == 16
    assert row[14] == ["php-probe"]
    assert '"body_head": "hi"' in row[15]


async def test_detail_omitted_when_not_kept():
    h = _hit()
    h.detail_kept = False
    assert hit_row(h)[15] is None


async def test_postgres_roundtrip(database_url):
    w = PostgresWriter(database_url, flush_interval=0.05)
    await w.start()
    await w.put(_hit("/integration"))
    await w.stop()
    conn = await asyncpg.connect(database_url)
    try:
        row = await conn.fetchrow("SELECT path, signatures, detail->>'body_head' AS head FROM sensor_hits WHERE path = '/integration' ORDER BY id DESC LIMIT 1")
        await conn.execute("DELETE FROM sensor_hits WHERE path = '/integration'")
    finally:
        await conn.close()
    assert row["path"] == "/integration"
    assert row["signatures"] == ["php-probe"]
    assert row["head"] == "hi"


class FlakyWriter(PostgresWriter):
    """Writer whose _insert is scripted by a callable."""

    def __init__(self, impl, **kw):
        super().__init__("postgresql://unused", **kw)
        self.inserted = []
        self._impl = impl

    async def _insert(self, rows):
        await self._impl(self, rows)


async def _put_paths(w, paths):
    for p in paths:
        await w.put(_hit(p))


def test_nul_bytes_sanitized():
    h = build_hit(src_ip="203.0.113.1", method="GET", path="/p\x00q", headers=[("X-Evil", "a\x00b")], body_bytes=0, multipart_parts=0, body_head=b"\x00zz")
    row = hit_row(h)
    assert "\x00" not in row[6]
    assert "\\u0000" not in row[15]
    assert "\x00" not in row[15]


async def test_poison_row_quarantined():
    async def impl(w, rows):
        if any(r[6] == "/bad" for r in rows):
            raise ValueError("bad row")
        w.inserted.extend(rows)

    w = FlakyWriter(impl)
    await _put_paths(w, ["/a", "/bad", "/c"])
    assert await w.flush() is True
    assert [r[6] for r in w.inserted] == ["/a", "/c"]
    assert w.rejected == 1
    assert len(w._buffer) == 0


async def test_transient_error_requeues_whole_batch():
    state = {"n": 0}

    async def impl(w, rows):
        state["n"] += 1
        if state["n"] == 1:
            raise OSError("down")
        w.inserted.extend(rows)

    w = FlakyWriter(impl)
    await _put_paths(w, ["/a", "/b", "/c"])
    assert await w.flush() is False
    assert [r[6] for r in w._buffer] == ["/a", "/b", "/c"]
    assert w.rejected == 0
    assert await w.flush() is True
    assert [r[6] for r in w.inserted] == ["/a", "/b", "/c"]


async def test_cancel_during_insert_requeues_batch():
    gate = asyncio.Event()

    async def impl(w, rows):
        await gate.wait()

    w = FlakyWriter(impl)
    await _put_paths(w, ["/a", "/b", "/c"])
    task = asyncio.create_task(w.flush())
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(w._buffer) == 3
    assert w._buffer[0][6] == "/a"


async def test_schema_failure_leaves_no_pool(monkeypatch):
    closed = []

    class FakePool:
        async def close(self):
            closed.append(True)

    async def fake_create_pool(*a, **kw):
        return FakePool()

    async def bad_schema(pool):
        raise RuntimeError("schema boom")

    monkeypatch.setattr(asyncpg, "create_pool", fake_create_pool)
    monkeypatch.setattr("php2mon.sensor.writer.apply_schema", bad_schema)
    w = PostgresWriter("postgresql://x")
    with pytest.raises(WriterSetupError):
        await w._insert([])
    assert w._pool is None
    assert closed == [True]


async def test_put_never_raises_on_bad_ip():
    w = RecordingWriter()
    h = _hit()
    h.src_ip = "not-an-ip"
    await w.put(h)
    assert w.rejected == 1
    assert len(w._buffer) == 0


async def test_failure_logging_is_rate_limited(caplog):
    async def impl(w, rows):
        raise OSError("down")

    w = FlakyWriter(impl)
    await _put_paths(w, ["/a"])
    with caplog.at_level(logging.WARNING, logger="php2mon.sensor.writer"):
        for _ in range(130):
            assert await w.flush() is False
    assert len([r for r in caplog.records if "insert failed" in r.getMessage()]) == 3


async def test_start_twice_is_idempotent():
    w = RecordingWriter(flush_interval=10)
    await w.start()
    first = w._task
    await w.start()
    assert w._task is first
    await w.stop()


def test_literal_backslash_u0000_survives():
    h = build_hit(src_ip="203.0.113.1", method="GET", path="/", headers=[("X-T", "x\\u0000y")], body_bytes=0, multipart_parts=0, body_head=b"abc\\u0000")
    detail = json.loads(hit_row(h)[15])
    assert detail["body_head"] == "abc\\u0000"
    assert detail["headers"]["x-t"] == "x\\u0000y"


async def test_setup_failure_requeues(monkeypatch):
    async def bad_pool(*a, **kw):
        raise RuntimeError("password authentication failed")

    monkeypatch.setattr(asyncpg, "create_pool", bad_pool)
    w = PostgresWriter("postgresql://x")
    await _put_paths(w, ["/a", "/b", "/c"])
    assert await w.flush() is False
    assert len(w._buffer) == 3
    assert w.rejected == 0
    assert w._pool is None


async def test_poison_detail_falls_back_to_no_detail():
    async def impl(w, rows):
        if any(isinstance(r[15], str) and "poison" in r[15] for r in rows):
            raise ValueError("bad detail")
        w.inserted.extend(rows)

    w = FlakyWriter(impl)
    h = build_hit(src_ip="203.0.113.1", method="GET", path="/x", headers=[("Host", "x")], body_bytes=0, multipart_parts=0, body_head=b"poison")
    h.resp_status = 200
    await w.put(h)
    assert await w.flush() is True
    assert len(w.inserted) == 1
    assert w.inserted[0][15] is None
    assert w.rejected == 0


async def test_per_row_path_resets_failure_counter():
    async def impl(w, rows):
        if any(r[6] == "/bad" for r in rows):
            raise ValueError("bad row")
        w.inserted.extend(rows)

    w = FlakyWriter(impl)
    await _put_paths(w, ["/a", "/bad"])
    w._consecutive_failures = 5
    assert await w.flush() is True
    assert w._consecutive_failures == 0


async def test_start_applies_schema_eagerly(monkeypatch):
    calls = []

    class FakePool:
        async def close(self):
            pass

    pool = FakePool()

    async def fake_create_pool(*a, **k):
        return pool

    async def fake_apply_schema(p):
        calls.append(p)

    monkeypatch.setattr("php2mon.sensor.writer.asyncpg.create_pool", fake_create_pool)
    monkeypatch.setattr("php2mon.sensor.writer.apply_schema", fake_apply_schema)
    w = PostgresWriter("postgresql://unused")
    await w.start()
    assert calls == [pool]
    assert w._pool is pool
    await w.stop()


async def test_start_survives_db_down(monkeypatch):
    async def fake_create_pool(*a, **k):
        raise OSError("db down")

    monkeypatch.setattr("php2mon.sensor.writer.asyncpg.create_pool", fake_create_pool)
    w = PostgresWriter("postgresql://unused")
    await w.start()
    assert w._pool is None
    await w.stop()
