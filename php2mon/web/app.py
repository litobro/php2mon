"""Read-only dashboard API and page.

The dashboard connects as the SELECT-only `php2mon_dashboard` role and never
writes. The `claims` table is seeded from claims.yaml by `load_claims`, which
`php2mon.dbinit` calls with the admin connection at startup.
"""

from __future__ import annotations

import hashlib
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import asyncpg
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from php2mon.claims import load_claims  # noqa: F401  (re-exported)

from . import queries

PATCH_RELEASE = datetime(2026, 10, 21, 14, 0, tzinfo=timezone.utc)
# Optional event markers on the timeline; set when the real times are known.
EMBARGO_END: datetime | None = None
CF_RULES_DEPLOYED: datetime | None = None

STATIC_DIR = Path(__file__).with_name("static")

# Reverse proxies / CDNs (Cloudflare) cache /static/*.js and *.woff2 by
# extension and will serve a stale asset across a deploy. index.html is served
# fresh, so stamp each local asset URL in it with a short content hash: a
# changed file yields a new URL, which is a guaranteed cache miss. Zero upkeep.
_ASSET_REF = re.compile(r'/static/([A-Za-z0-9_./-]+?\.(?:js|css|woff2|png|svg))')


def _versioned_index_html() -> str:
    html = (STATIC_DIR / "index.html").read_text()

    def stamp(m: re.Match[str]) -> str:
        rel = m.group(1)
        try:
            digest = hashlib.md5((STATIC_DIR / rel).read_bytes()).hexdigest()[:8]
        except OSError:
            return m.group(0)
        return f"/static/{rel}?v={digest}"

    return _ASSET_REF.sub(stamp, html)


def create_app(dsn: str | None = None, patch_release: datetime = PATCH_RELEASE) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.pool = await asyncpg.create_pool(
            dsn or os.environ["DATABASE_URL"], min_size=1, max_size=4
        )
        try:
            yield
        finally:
            await app.state.pool.close()

    app = FastAPI(title="php2mon", lifespan=lifespan, docs_url=None, redoc_url=None)

    def iso(d: datetime | None) -> str | None:
        return d.isoformat() if d else None

    @app.get("/api/headline")
    async def headline():
        data = await queries.headline(app.state.pool, patch_release)
        return {"patch_release": patch_release.isoformat(), **data}

    @app.get("/api/timeline")
    async def timeline(window: str | None = None):
        hours = queries.window_hours(window)
        data = await queries.timeline(app.state.pool, hours)
        data["window_hours"] = hours
        data["annotations"] = {
            "patch_release": patch_release.isoformat(),
            "embargo": iso(EMBARGO_END),
            "cf_rules": iso(CF_RULES_DEPLOYED),
            "kev": data.pop("kev"),
        }
        return data

    @app.get("/api/sources")
    async def sources(window: str | None = None):
        hours = queries.window_hours(window)
        return {"window_hours": hours, "rows": await queries.sources(app.state.pool, hours)}

    @app.get("/api/iocs")
    async def iocs(window: str | None = None):
        hours = queries.window_hours(window)
        return {"window_hours": hours, "iocs": await queries.exploit_iocs(app.state.pool, hours)}

    @app.get("/api/adoption")
    async def adoption():
        return {"series": await queries.adoption(app.state.pool)}

    @app.get("/api/claims")
    async def claims():
        return {"claims": await queries.claims(app.state.pool)}

    @app.get("/api/status")
    async def status():
        return {"collectors": await queries.status(app.state.pool)}

    index_html = _versioned_index_html()

    @app.get("/", include_in_schema=False)
    async def index():
        # no-store keeps the CDN/browser from caching the page, so updated
        # asset hashes are always seen on the next load.
        return HTMLResponse(index_html, headers={"Cache-Control": "no-store"})

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app
