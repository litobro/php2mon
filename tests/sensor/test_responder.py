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
    reply = respond(persona, _hit(), has_session=False, host="decoy.test", port=80)
    assert reply.status == 200
    assert reply.headers["Server"] == persona.server
    assert reply.headers["X-Powered-By"] == persona.x_powered_by
    assert reply.headers["Content-Type"] == "text/html; charset=UTF-8"
    cookie = reply.headers["Set-Cookie"]
    assert re.fullmatch(r"^PHPSESSID=[0-9a-v]{26}; path=/$", cookie)
    assert "HttpOnly" not in cookie
    for name, value in CACHE_HEADERS.items():
        assert reply.headers[name] == value
    assert reply.body == persona.pages["/"].encode()


def test_existing_session_gets_no_cookie():
    persona = load_persona(EXAMPLE)
    reply = respond(persona, _hit(), has_session=True, host="decoy.test", port=80)
    assert "Set-Cookie" not in reply.headers
    for name, value in CACHE_HEADERS.items():
        assert reply.headers[name] == value


def test_unknown_page_returns_404():
    persona = load_persona(EXAMPLE)
    reply = respond(persona, _hit(path="/nope.php"), has_session=False, host="decoy.test", port=80)
    assert reply.status == 404
    assert reply.body == persona.not_found.replace("{host}", "decoy.test").replace("{port}", "80").encode()
    assert reply.headers == {"Server": persona.server, "Content-Type": "text/html; charset=iso-8859-1"}


def test_large_multipart_triggers_fatal_500():
    persona = load_persona(EXAMPLE)
    hit = _hit(
        method="POST",
        headers=[("Content-Type", "multipart/form-data; boundary=x")],
        body_bytes=persona.memory_trigger.min_body_bytes,
        multipart_parts=1,
    )
    assert memory_trigger_fires(persona, hit)
    reply = respond(persona, hit, has_session=False, host="decoy.test", port=80)
    assert reply.status == 500
    assert str(hit.body_bytes).encode() in reply.body
    assert set(reply.headers) == {"Server", "X-Powered-By", "Content-Type"}
    assert reply.headers["X-Powered-By"] == persona.x_powered_by
    assert reply.headers["Content-Type"] == "text/html; charset=UTF-8"


def test_large_non_multipart_does_not_trigger_when_multipart_only():
    persona = load_persona(EXAMPLE)
    hit = _hit(
        method="POST",
        headers=[("Content-Type", "application/octet-stream")],
        body_bytes=persona.memory_trigger.min_body_bytes * 2,
    )
    assert not memory_trigger_fires(persona, hit)


def _static_persona():
    persona = load_persona(EXAMPLE)
    pages = dict(persona.pages)
    pages["/style.css"] = "body{}"
    pages["/readme.html"] = "<html></html>"
    pages["/blob.zzunknown"] = "?"
    return persona.model_copy(update={"pages": pages})


def _big_multipart(persona, path):
    return _hit(
        method="POST",
        path=path,
        headers=[("Content-Type", "multipart/form-data; boundary=x")],
        body_bytes=persona.memory_trigger.min_body_bytes * 2,
        multipart_parts=10,
    )


def test_static_page_is_served_without_php_headers():
    persona = _static_persona()
    reply = respond(persona, _hit(path="/style.css"), has_session=False, host="decoy.test", port=80)
    assert reply.status == 200
    assert reply.headers == {"Server": persona.server, "Accept-Ranges": "bytes", "Content-Type": "text/css"}
    assert reply.body == b"body{}"


def test_static_content_types():
    persona = _static_persona()
    html = respond(persona, _hit(path="/readme.html"), has_session=False, host="h", port=80)
    assert html.headers["Content-Type"] == "text/html"
    other = respond(persona, _hit(path="/blob.zzunknown"), has_session=False, host="h", port=80)
    assert other.headers["Content-Type"] == "application/octet-stream"


def test_large_multipart_to_non_php_paths_does_not_trigger_fatal():
    persona = _static_persona()
    missing = respond(persona, _big_multipart(persona, "/nope"), has_session=False, host="h", port=80)
    assert missing.status == 404
    static = respond(persona, _big_multipart(persona, "/style.css"), has_session=False, host="h", port=80)
    assert static.status == 200
    php = respond(persona, _big_multipart(persona, "/index.php"), has_session=False, host="h", port=80)
    assert php.status == 500


def test_not_found_substitutes_host_and_port():
    persona = load_persona(EXAMPLE).model_copy(update={"not_found": "Server at {host} Port {port}"})
    reply = respond(persona, _hit(path="/nope"), has_session=False, host="&lt;x&gt;", port=8443)
    assert reply.body == b"Server at &lt;x&gt; Port 8443"


def test_persona_server_name_defaults_to_localhost():
    assert load_persona(EXAMPLE).server_name == "localhost"
