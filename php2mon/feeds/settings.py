"""Collector settings, loaded from the environment. Empty strings count as unset."""
from __future__ import annotations
import os

from pydantic import BaseModel


class Settings(BaseModel):
    database_url: str
    contact_email: str | None = None
    cf_radar_token: str | None = None
    shodan_api_key: str | None = None
    geoip_dir: str = "/geoip"

    @classmethod
    def from_env(cls, env=None) -> "Settings":
        env = os.environ if env is None else env

        def get(name: str) -> str | None:
            return env.get(name) or None

        values = {
            "database_url": get("DATABASE_URL"),
            "contact_email": get("CONTACT_EMAIL"),
            "cf_radar_token": get("CF_RADAR_TOKEN"),
            "shodan_api_key": get("SHODAN_API_KEY"),
            "geoip_dir": get("GEOIP_DIR"),
        }
        return cls(**{k: v for k, v in values.items() if v is not None or k not in ("database_url", "geoip_dir")})
