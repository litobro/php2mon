"""Read-only dashboard API and page.

The dashboard connects as the SELECT-only `php2mon_dashboard` role and never
writes. The `claims` table is seeded from claims.yaml by `load_claims`, which
`php2mon.dbinit` calls with the admin connection at startup.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import asyncpg
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from php2mon.claims import load_claims  # noqa: F401  (re-exported)

from . import queries

PATCH_RELEASE = datetime(2026, 10, 21, 14, 0, tzinfo=timezone.utc)
# Optional event markers on the timeline; set when the real times are known.
EMBARGO_END: datetime | None = None
CF_RULES_DEPLOYED: datetime | None = None

STATIC_DIR = Path(__file__).with_name("static")


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

    @app.get("/api/adoption")
    async def adoption():
        return {"series": await queries.adoption(app.state.pool)}

    @app.get("/api/claims")
    async def claims():
        return {"claims": await queries.claims(app.state.pool)}

    @app.get("/api/status")
    async def status():
        return {"collectors": await queries.status(app.state.pool)}

    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app
