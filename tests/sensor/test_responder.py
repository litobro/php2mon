import re
from pathlib import Path

from php2mon.sensor.hits import build_hit
from php2mon.sensor.persona import load_persona
from php2mon.sensor.responder import memory_trigger_fires, respond

EXAMPLE = Path(__file__).resolve().parents[2] / "config.example" / "persona.yaml"

CACHE_HEADERS = {
    "Expires": "Thu, 19 Nov 1981 08:52:00 GMT",
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
}


def _hit(**kw):
    base = dict(
        src_ip="203.0.113.1",
        method="GET",
        path="/",
        headers=[],
        body_bytes=0,
        multipart_parts=0,
        body_head=b"",
    )
    base.update(kw)
    return build_hit(**base)


def test_known_page_returns_200_with_persona_headers():
    persona = load_persona(EXAMPLE)
    reply = respond(persona, _hit(), has_session=False)
    assert reply.status == 200
    assert reply.headers["Server"] == persona.server
    assert reply.headers["X-Powered-By"] == persona.x_powered_by
    assert reply.headers["Content-Type"] == "text/html; charset=UTF-8"
    cookie = reply.headers["Set-Cookie"]
    assert re.fullmatch(r"PHPSESSID=[0-9a-f]{32}; path=/", cookie)
    assert "HttpOnly" not in cookie
    for name, value in CACHE_HEADERS.items():
        assert reply.headers[name] == value
    assert reply.body == persona.pages["/"].encode()


def test_existing_session_gets_no_cookie():
    persona = load_persona(EXAMPLE)
    reply = respond(persona, _hit(), has_session=True)
    assert "Set-Cookie" not in reply.headers
    for name, value in CACHE_HEADERS.items():
        assert reply.headers[name] == value


def test_unknown_page_returns_404():
    persona = load_persona(EXAMPLE)
    reply = respond(persona, _hit(path="/nope.php"), has_session=False)
    assert reply.status == 404
    assert reply.body == persona.not_found.encode()
    assert "Set-Cookie" not in reply.headers
    assert "Cache-Control" not in reply.headers
    assert reply.headers["Content-Type"] == "text/html; charset=iso-8859-1"


def test_large_multipart_triggers_fatal_500():
    persona = load_persona(EXAMPLE)
    hit = _hit(
        method="POST",
        headers=[("Content-Type", "multipart/form-data; boundary=x")],
        body_bytes=persona.memory_trigger.min_body_bytes,
        multipart_parts=1,
    )
    assert memory_trigger_fires(persona, hit)
    reply = respond(persona, hit, has_session=False)
    assert reply.status == 500
    assert str(hit.body_bytes).encode() in reply.body
    assert "Set-Cookie" not in reply.headers
    assert "Cache-Control" not in reply.headers


def test_large_non_multipart_does_not_trigger_when_multipart_only():
    persona = load_persona(EXAMPLE)
    hit = _hit(
        method="POST",
        headers=[("Content-Type", "application/octet-stream")],
        body_bytes=persona.memory_trigger.min_body_bytes * 2,
    )
    assert not memory_trigger_fires(persona, hit)
