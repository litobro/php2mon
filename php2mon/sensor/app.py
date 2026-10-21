"""The decoy ASGI app: read, classify, log, reply. Never executes anything."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import ClientDisconnect, Request
from starlette.responses import Response
from starlette.routing import Route

from php2mon.sensor.config import ConfigWatcher
from php2mon.sensor.geoip import GeoLookup
from php2mon.sensor.hits import BODY_HEAD_CAP, MultipartCounter, build_hit
from php2mon.sensor.ratelimit import RateLimiter
from php2mon.sensor.responder import respond
from php2mon.sensor.writer import HitSink

log = logging.getLogger(__name__)

DEFAULT_BODY_CAP = 32 * 1024 * 1024


class _AnyMethod:
    """ASGI endpoint wrapper. Route filters methods only for function endpoints, never for ASGI apps."""

    def __init__(self, handler) -> None:
        self._handler = handler

    async def __call__(self, scope, receive, send) -> None:
        response = await self._handler(Request(scope, receive))
        await response(scope, receive, send)


def create_app(
    config_dir: Path,
    sink: HitSink,
    *,
    geo: GeoLookup | None = None,
    limiter: RateLimiter | None = None,
    body_cap: int = DEFAULT_BODY_CAP,
    body_timeout: float = 30.0,
    lifespan=None,
) -> Starlette:
    watcher = ConfigWatcher(config_dir)

    async def handle(request: Request) -> Response:
        try:
            watcher.maybe_reload()
            persona, evaluator = watcher.persona, watcher.evaluator
            counter = MultipartCounter.from_content_type(request.headers.get("content-type"))
            total = 0
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
                headers=request.headers.items(),
                body_bytes=total,
                multipart_parts=counter.parts if counter is not None else 0,
                body_head=head,
                session_cookie=persona.session_cookie,
            )
            reply = respond(persona, hit, has_session=hit.sess_len > 0)
            hit.resp_status = reply.status
            hit.signatures = evaluator.evaluate(hit)
            if geo is not None:
                geo.enrich(hit)
            if limiter is not None and not limiter.allow(hit.src_ip):
                hit.detail_kept = False
            await sink.put(hit)
            if request.method == "HEAD":
                headers = dict(reply.headers)
                headers["Content-Length"] = str(len(reply.body))
                return Response(b"", status_code=reply.status, headers=headers)
            return Response(reply.body, status_code=reply.status, headers=reply.headers)
        except Exception:
            log.exception("sensor handler failed")
            persona = watcher.persona
            return Response(
                persona.fatal.replace("{bytes}", "0").encode(),
                status_code=500,
                headers={
                    "Server": persona.server,
                    "X-Powered-By": persona.x_powered_by,
                    "Content-Type": "text/html; charset=UTF-8",
                },
            )

    return Starlette(routes=[Route("/{path:path}", _AnyMethod(handle))], lifespan=lifespan)
