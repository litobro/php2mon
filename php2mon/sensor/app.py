"""The decoy ASGI app: read, classify, log, reply. Never executes anything."""

from __future__ import annotations

import asyncio
import html
import logging
from email.utils import formatdate
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import ClientDisconnect, Request
from starlette.routing import Route

from php2mon.sensor.config import ConfigWatcher
from php2mon.sensor.geoip import GeoLookup
from php2mon.sensor.hits import BODY_HEAD_CAP, MultipartCounter, build_hit
from php2mon.sensor.ratelimit import RateLimiter
from php2mon.sensor.responder import Reply, respond
from php2mon.sensor.writer import HitSink

log = logging.getLogger(__name__)

DEFAULT_BODY_CAP = 32 * 1024 * 1024


# Apache's order. Names are sent exactly as written here: h11 keeps header case.
RESPONSE_HEADER_ORDER = (
    "Date",
    "Server",
    "X-Powered-By",
    "Set-Cookie",
    "Expires",
    "Cache-Control",
    "Pragma",
    "Accept-Ranges",
    "Content-Length",
    "Content-Type",
)


def wire_headers(headers: dict[str, str], content_length: int) -> list[tuple[bytes, bytes]]:
    values = {**headers, "Date": formatdate(usegmt=True), "Content-Length": str(content_length)}
    return [
        (name.encode("latin-1"), values[name].encode("latin-1"))
        for name in RESPONSE_HEADER_ORDER
        if name in values
    ]


class _AnyMethod:
    """ASGI endpoint wrapper. Route filters methods only for function endpoints, never for ASGI apps."""

    def __init__(self, handler) -> None:
        self._handler = handler

    async def __call__(self, scope, receive, send) -> None:
        reply = await self._handler(Request(scope, receive))
        await send({
            "type": "http.response.start",
            "status": reply.status,
            "headers": wire_headers(reply.headers, len(reply.body)),
        })
        await send({"type": "http.response.body", "body": b"" if scope["method"] == "HEAD" else reply.body})


def host_and_port(request: Request, default_host: str) -> tuple[str, int]:
    """The name and port Apache would print in its error pages, taken from the Host header."""
    raw = request.headers.get("host", "")
    name, sep, port = raw.rpartition(":")
    if sep and port.isascii() and port.isdigit():
        host, port_num = name, int(port)
    else:
        host, port_num = raw, 443 if request.url.scheme == "https" else 80
    return html.escape(host) if host else html.escape(default_host), port_num


def create_app(
    config_dir: Path,
    sink: HitSink,
    *,
    state_dir: Path | None = None,
    geo: GeoLookup | None = None,
    limiter: RateLimiter | None = None,
    body_cap: int = DEFAULT_BODY_CAP,
    body_timeout: float = 30.0,
    lifespan=None,
) -> Starlette:
    watcher = ConfigWatcher(config_dir, state_dir=state_dir)

    async def record_failed(request: Request, body_bytes: int) -> None:
        """Best effort: keep a minimal row for a request the handler could not finish."""
        try:
            hit = build_hit(
                src_ip=request.client.host if request.client else "0.0.0.0",
                method=request.method,
                path=request.url.path,
                query=request.scope["query_string"].decode("latin-1"),
                headers=request.headers.items(),
                body_bytes=body_bytes,
                multipart_parts=0,
                body_head=b"",
            )
            hit.resp_status = 500
            hit.signatures = ["handler-error"]
            await sink.put(hit)
        except Exception as exc:
            log.warning("could not record failed request: %s", exc)

    async def handle(request: Request) -> Reply:
        total = 0
        try:
            watcher.maybe_reload()
            if geo is not None:
                geo.maybe_reopen()
            persona, evaluator = watcher.persona, watcher.evaluator
            counter = MultipartCounter.from_content_type(request.headers.get("content-type"))
            head = b""
            src_ip = request.client.host if request.client else "0.0.0.0"
            try:
                async with asyncio.timeout(body_timeout):
                    async for chunk in request.stream():
                        total += len(chunk)
                        if len(head) < BODY_HEAD_CAP:
                            head += chunk[: BODY_HEAD_CAP - len(head)]
                        if counter is not None:
                            counter.feed(chunk)
                        if total >= body_cap:
                            total = body_cap
                            break
            except ClientDisconnect:
                log.info("client %s disconnected after %d body bytes", src_ip, total)
            except TimeoutError:
                log.info("body read from %s timed out after %d bytes", src_ip, total)
            hit = build_hit(
                src_ip=src_ip,
                method=request.method,
                path=request.url.path,
                query=request.scope["query_string"].decode("latin-1"),
                headers=request.headers.items(),
                body_bytes=total,
                multipart_parts=counter.parts if counter is not None else 0,
                body_head=head,
                session_cookie=persona.session_cookie,
            )
            host, port = host_and_port(request, persona.server_name)
            reply = respond(persona, hit, has_session=hit.sess_len > 0, host=host, port=port)
            hit.resp_status = reply.status
            hit.signatures = evaluator.evaluate(hit)
            if geo is not None:
                geo.enrich(hit)
            if limiter is not None and not limiter.allow(hit.src_ip):
                hit.detail_kept = False
            await sink.put(hit)
            return reply
        except Exception:
            log.exception("sensor handler failed")
            await record_failed(request, total)
            persona = watcher.persona
            return Reply(
                500,
                {
                    "Server": persona.server,
                    "X-Powered-By": persona.x_powered_by,
                    "Content-Type": "text/html; charset=UTF-8",
                },
                persona.fatal.replace("{bytes}", "0").encode(),
            )

    return Starlette(routes=[Route("/{path:path}", _AnyMethod(handle))], lifespan=lifespan)
