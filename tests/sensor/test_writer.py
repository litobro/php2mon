import asyncpg
import pytest

from php2mon.sensor.hits import build_hit
from php2mon.sensor.writer import MemorySink, PostgresWriter, hit_row


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
