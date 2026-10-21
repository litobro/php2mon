"""Raw-socket checks of what the sensor actually puts on the wire under uvicorn and h11."""

import socket
import threading
import time
from pathlib import Path

import pytest
import uvicorn

from php2mon.sensor.app import RESPONSE_HEADER_ORDER, create_app
from php2mon.sensor.persona import load_persona
from php2mon.sensor.writer import MemorySink

EXAMPLE = Path(__file__).resolve().parents[2] / "config.example"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def server():
    port = _free_port()
    config = uvicorn.Config(
        create_app(EXAMPLE, MemorySink()),
        host="127.0.0.1",
        port=port,
        http="h11",
        date_header=False,
        server_header=False,
        h11_max_incomplete_event_size=65536,
        access_log=False,
        log_level="warning",
        lifespan="off",
    )
    srv = uvicorn.Server(config)
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not srv.started:
        assert time.monotonic() < deadline, "uvicorn did not start"
        time.sleep(0.01)
    yield port
    srv.should_exit = True
    thread.join(timeout=10)


def _raw(port: int, request: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(request)
        chunks = []
        while chunk := s.recv(65536):
            chunks.append(chunk)
    return b"".join(chunks)


def _header_lines(response: bytes) -> list[str]:
    head = response.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    return head.split("\r\n")[1:]


def test_headers_are_canonical_case_in_apache_order(server):
    persona = load_persona(EXAMPLE / "persona.yaml")
    response = _raw(server, b"GET / HTTP/1.1\r\nHost: decoy.test\r\nConnection: close\r\n\r\n")
    assert response.startswith(b"HTTP/1.1 200 OK\r\n")
    lines = _header_lines(response)
    names = [line.split(":", 1)[0] for line in lines if not line.startswith("Connection:")]
    assert names == [
        "Date",
        "Server",
        "X-Powered-By",
        "Set-Cookie",
        "Expires",
        "Cache-Control",
        "Pragma",
        "Content-Length",
        "Content-Type",
    ]
    assert names == [n for n in RESPONSE_HEADER_ORDER if n in names]
    assert f"Server: {persona.server}" in lines
    assert any(line.startswith("Date: ") and line.endswith(" GMT") for line in lines)
    assert not any(line.startswith(("server:", "date:")) for line in lines)
    assert b"uvicorn" not in response.lower()
    body = response.split(b"\r\n\r\n", 1)[1]
    assert f"Content-Length: {len(body)}" in lines


def test_large_cookie_header_is_accepted(server):
    cookie = b"a=" + b"c" * 40_000
    response = _raw(server, b"GET / HTTP/1.1\r\nHost: decoy.test\r\nCookie: " + cookie + b"\r\nConnection: close\r\n\r\n")
    assert response.startswith(b"HTTP/1.1 200 OK\r\n")


def test_head_sends_get_length_and_no_body(server):
    persona = load_persona(EXAMPLE / "persona.yaml")
    response = _raw(server, b"HEAD / HTTP/1.1\r\nHost: decoy.test\r\nConnection: close\r\n\r\n")
    assert f"Content-Length: {len(persona.pages['/'].encode())}" in _header_lines(response)
    assert response.endswith(b"\r\n\r\n")
