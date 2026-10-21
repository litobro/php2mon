"""Fault-tolerant HTTP JSON fetch and raw-response persistence for feeds."""
from __future__ import annotations
import json as _json
from dataclasses import dataclass
import httpx


@dataclass
class FeedResult:
    ok: bool
    status: int | None
    json: object | None
    text: str | None
    error: str | None


async def fetch_json(client, url, *, params=None, headers=None, timeout=20.0) -> FeedResult:
    try:
        resp = await client.get(url, params=params, headers=headers, timeout=timeout)
    except Exception as exc:
        return FeedResult(False, None, None, None, f"{type(exc).__name__}: {exc}")
    if resp.status_code // 100 != 2:
        return FeedResult(False, resp.status_code, None, resp.text[:2000], f"HTTP {resp.status_code}")
    try:
        return FeedResult(True, resp.status_code, resp.json(), None, None)
    except Exception as exc:
        return FeedResult(False, resp.status_code, None, resp.text[:2000], f"decode: {exc}")


async def store_raw(conn, source: str, payload: object) -> None:
    await conn.execute(
        "INSERT INTO feed_raw (ts, source, payload) VALUES (now(), $1, $2::jsonb)",
        source, _json.dumps(payload),
    )
