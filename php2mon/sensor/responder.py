"""Decide what the decoy sends back for a given hit."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from php2mon.sensor.hits import HitRecord
from php2mon.sensor.persona import Persona

# PHP's session cache-limiter headers, sent on every page response.
CACHE_HEADERS = {
    "Expires": "Thu, 19 Nov 1981 08:52:00 GMT",
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
}


@dataclass
class Reply:
    status: int
    headers: dict[str, str]
    body: bytes


def new_session_id() -> str:
    return secrets.token_hex(16)


def memory_trigger_fires(persona: Persona, hit: HitRecord) -> bool:
    trigger = persona.memory_trigger
    if hit.body_bytes < trigger.min_body_bytes:
        return False
    if trigger.multipart_only and not (hit.content_type or "").lower().startswith("multipart/"):
        return False
    return True


def respond(persona: Persona, hit: HitRecord, *, has_session: bool) -> Reply:
    headers = {
        "Server": persona.server,
        "X-Powered-By": persona.x_powered_by,
        "Content-Type": "text/html; charset=UTF-8",
    }
    if memory_trigger_fires(persona, hit):
        body = persona.fatal.replace("{bytes}", str(hit.body_bytes))
        return Reply(500, headers, body.encode())
    page = persona.pages.get(hit.path)
    if page is None:
        headers["Content-Type"] = "text/html; charset=iso-8859-1"
        return Reply(404, headers, persona.not_found.encode())
    headers.update(CACHE_HEADERS)
    if not has_session:
        headers["Set-Cookie"] = f"{persona.session_cookie}={new_session_id()}; path=/"
    return Reply(200, headers, page.encode())
