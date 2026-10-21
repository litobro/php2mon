"""Run the decoy sensor: python -m php2mon.sensor"""

from __future__ import annotations

import contextlib
import logging
import os
from pathlib import Path

import uvicorn

from php2mon.sensor.app import DEFAULT_BODY_CAP, create_app
from php2mon.sensor.geoip import GeoLookup
from php2mon.sensor.ratelimit import RateLimiter
from php2mon.sensor.writer import PostgresWriter


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    config_dir = Path(os.environ.get("CONFIG_DIR", "/config"))
    writer = PostgresWriter(os.environ["DATABASE_URL"])

    @contextlib.asynccontextmanager
    async def lifespan(app):
        await writer.start()
        try:
            yield
        finally:
            await writer.stop()

    app = create_app(
        config_dir,
        writer,
        geo=GeoLookup.from_dir(config_dir / "geoip"),
        limiter=RateLimiter(int(os.environ.get("RATE_PER_MINUTE", "120"))),
        body_cap=int(os.environ.get("BODY_CAP", str(DEFAULT_BODY_CAP))),
        body_timeout=float(os.environ.get("BODY_TIMEOUT", "30")),
        lifespan=lifespan,
    )
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8080")),
        ssl_certfile=os.environ.get("SSL_CERTFILE"),
        ssl_keyfile=os.environ.get("SSL_KEYFILE"),
        http="h11",
        date_header=False,
        server_header=False,
        h11_max_incomplete_event_size=65536,
        access_log=False,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
