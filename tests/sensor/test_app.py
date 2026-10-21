import asyncio
import logging
from pathlib import Path

import httpx
import pytest
from starlette.requests import ClientDisconnect, Request

from php2mon.sensor.app import create_app
from php2mon.sensor.persona import load_persona
from php2mon.sensor.ratelimit import RateLimiter
from php2mon.sensor.writer import MemorySink

EXAMPLE = Path(__file__).resolve().parents[2] / "config.example"


@pytest.fixture
def persona():
    return load_persona(EXAMPLE / "persona.yaml")


def _client(app, ip="203.0.113.7"):
    transport = httpx.ASGITransport(app=app, client=(ip, 4444))
    return httpx.AsyncClient(transport=transport, base_url="http://decoy.test")


async def test_get_root_serves_persona_and_logs(persona):
    sink = MemorySink()
    async with _client(create_app(EXAMPLE, sink)) as c:
        r = await c.get("/")
    assert r.status_code == 200
    assert r.headers["server"] == persona.server
    assert r.headers["x-powered-by"] == persona.x_powered_by
    assert "PHPSESSID=" in r.headers["set-cookie"]
    assert r.text == persona.pages["/"]
    assert len(sink.hits) == 1
    hit = sink.hits[0]
    assert hit.src_ip == "203.0.113.7"
    assert hit.path == "/"
    assert hit.resp_status == 200
    assert hit.host == "decoy.test"


async def test_any_method_and_unknown_path_logged_as_404():
    sink = MemorySink()
    async with _client(create_app(EXAMPLE, sink)) as c:
        r = await c.request("PROPFIND", "/.env")
    assert r.status_code == 404
    assert sink.hits[0].method == "PROPFIND"


async def test_large_multipart_gets_500_and_signatures(persona):
    sink = MemorySink()
    boundary = "b0undary"
    part = f"--{boundary}\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n".encode() + b"A" * 1024 + b"\r\n"
    body = part * (persona.memory_trigger.min_body_bytes // len(part) + 1) + f"--{boundary}--\r\n".encode()
    async with _client(create_app(EXAMPLE, sink)) as c:
        r = await c.post("/index.php", content=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    assert r.status_code == 500
    assert "Allowed memory size" in r.text
    hit = sink.hits[0]
    assert hit.body_bytes == len(body)
    assert hit.multipart_parts > 100
    assert "multipart-large" in hit.signatures
    assert "php-probe" in hit.signatures


async def test_body_over_cap_is_truncated_but_still_answered():
    sink = MemorySink()
    cap = 10_000
    async with _client(create_app(EXAMPLE, sink, body_cap=cap)) as c:
        r = await c.post("/", content=b"x" * (cap * 3), headers={"Content-Type": "application/octet-stream"})
    assert r.status_code == 200
    assert sink.hits[0].body_bytes == cap


async def test_rate_limited_hit_loses_detail_only():
    sink = MemorySink()
    app = create_app(EXAMPLE, sink, limiter=RateLimiter(per_minute=1))
    async with _client(app) as c:
        await c.get("/")
        await c.get("/")
    assert [h.detail_kept for h in sink.hits] == [True, False]


async def test_head_request_has_no_body(persona):
    sink = MemorySink()
    async with _client(create_app(EXAMPLE, sink)) as c:
        r = await c.head("/")
    assert r.status_code == 200
    assert r.content == b""
    assert r.headers["content-length"] == str(len(persona.pages["/"].encode()))


async def test_sink_failure_still_answers(persona, caplog):
    class BadSink:
        async def put(self, hit):
            raise RuntimeError("boom")

    async with _client(create_app(EXAMPLE, BadSink())) as c:
        r = await c.get("/")
    assert r.status_code == 500
    assert r.headers["server"] == persona.server
    assert "sensor handler failed" in caplog.text


async def test_client_disconnect_mid_body_logs_partial_hit(monkeypatch, caplog):
    async def stream(self):
        yield b"x" * 100
        raise ClientDisconnect()

    monkeypatch.setattr(Request, "stream", stream)
    sink = MemorySink()
    with caplog.at_level(logging.INFO):
        async with _client(create_app(EXAMPLE, sink)) as c:
            await c.post("/", content=b"x")
    assert sink.hits[0].body_bytes == 100
    assert "sensor handler failed" not in caplog.text
    assert any("disconnected" in r.message and r.levelno == logging.INFO for r in caplog.records)


async def test_slow_body_times_out_and_logs(monkeypatch, caplog):
    async def stream(self):
        yield b"y" * 50
        await asyncio.sleep(5)
        yield b"z"

    monkeypatch.setattr(Request, "stream", stream)
    sink = MemorySink()
    with caplog.at_level(logging.INFO):
        async with _client(create_app(EXAMPLE, sink, body_timeout=0.05)) as c:
            r = await c.post("/", content=b"x")
    assert r.status_code == 200
    assert sink.hits[0].body_bytes == 50
    assert "timed out" in caplog.text


async def test_query_string_is_kept_and_page_lookup_is_path_only(persona):
    sink = MemorySink()
    async with _client(create_app(EXAMPLE, sink)) as c:
        r = await c.get("/index.php?s=/x&y=1")
    assert r.status_code == 200
    assert sink.hits[0].path == "/index.php"
    assert sink.hits[0].query == "s=/x&y=1"


async def test_not_found_renders_escaped_host_and_port():
    sink = MemorySink()
    async with _client(create_app(EXAMPLE, sink)) as c:
        r = await c.get("/nope", headers={"Host": "<x>:8443"})
    assert r.status_code == 404
    assert "&lt;x&gt;" in r.text and "<x>" not in r.text
    assert "Port 8443" in r.text


async def test_not_found_port_defaults_from_scheme():
    sink = MemorySink()
    transport = httpx.ASGITransport(app=create_app(EXAMPLE, sink), client=("203.0.113.7", 4444))
    async with httpx.AsyncClient(transport=transport, base_url="https://decoy.test") as c:
        r = await c.get("/nope")
    assert "decoy.test Port 443" in r.text
    async with _client(create_app(EXAMPLE, sink)) as c:
        r = await c.get("/nope")
    assert "decoy.test Port 80" in r.text


async def test_large_multipart_to_missing_path_is_404(persona):
    sink = MemorySink()
    body = b"--b\r\n" + b"A" * (persona.memory_trigger.min_body_bytes + 10)
    async with _client(create_app(EXAMPLE, sink)) as c:
        r = await c.post("/nope", content=body, headers={"Content-Type": "multipart/form-data; boundary=b"})
    assert r.status_code == 404


async def test_fallback_500_sends_headers_in_order(persona):
    class BadSink:
        async def put(self, hit):
            raise RuntimeError("boom")

    async with _client(create_app(EXAMPLE, BadSink())) as c:
        r = await c.get("/")
    names = [name for name, _ in r.headers.raw]
    assert names == [b"Date", b"Server", b"X-Powered-By", b"Content-Length", b"Content-Type"]
    assert r.headers["content-length"] == str(len(r.content))
