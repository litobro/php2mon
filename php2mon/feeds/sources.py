"""The four feed collectors: SANS ISC, Cloudflare Radar, CISA KEV, Shodan."""
from __future__ import annotations
import os
from datetime import UTC, datetime

from php2mon.feeds.base import Collector, Observation
from php2mon.feeds.client import fetch_json, store_raw

TRACKED_CVES = ("CVE-2026-109618", "CVE-2026-109619")
FIXED_VERSIONS = ("8.2.35", "8.3.36", "8.4.27", "8.5.12")


def _hour_now() -> datetime:
    return datetime.now(UTC).replace(minute=0, second=0, microsecond=0)


def _setting(ctx, name: str) -> str | None:
    """Read a setting from ctx.settings, falling back to the environment."""
    val = getattr(getattr(ctx, "settings", None), name, None) or os.environ.get(name.upper())
    return val or None


async def _fetch(ctx, source: str, url: str, **kw):
    res = await fetch_json(ctx.client, url, **kw)
    if not res.ok:
        raise RuntimeError(f"{source}: {res.error}")
    async with ctx.pool.acquire() as conn:
        await store_raw(conn, source, res.json)
    return res.json


class IscWebHoneypot(Collector):
    name = "isc"
    interval_seconds = 3600
    URL = "https://isc.sans.edu/api/webhoneypotsummary/{day}?json"

    @classmethod
    def parse(cls, payload) -> list[Observation]:
        summary = payload["webhoneypotsummary"]
        if isinstance(summary, list):
            summary = summary[0]
        ts = _hour_now()
        return [
            Observation(cls.name, f"isc_{k}", {}, float(summary[k]), ts)
            for k in ("reports", "targets", "sources") if k in summary
        ]

    async def collect(self, ctx) -> list[Observation]:
        contact = _setting(ctx, "contact_email")
        if not contact:
            raise RuntimeError("isc: CONTACT_EMAIL not set")
        day = datetime.now(UTC).date().isoformat()
        payload = await _fetch(ctx, self.name, self.URL.format(day=day),
                               headers={"User-Agent": f"php2mon ({contact})"})
        return self.parse(payload)


class CloudflareRadar(Collector):
    name = "radar"
    interval_seconds = 3600
    URL = "https://api.cloudflare.com/client/v4/radar/attacks/layer7/timeseries"

    @classmethod
    def parse(cls, payload) -> list[Observation]:
        serie = payload["result"]["serie_0"]
        return [
            Observation(cls.name, "l7_attacks", {},
                        float(v), datetime.fromisoformat(t.replace("Z", "+00:00")))
            for t, v in zip(serie["timestamps"], serie["values"])
        ]

    async def collect(self, ctx) -> list[Observation]:
        token = _setting(ctx, "cf_radar_token")
        if not token:
            return []
        payload = await _fetch(
            ctx, self.name, self.URL,
            params={"dateRange": "2d", "aggInterval": "1h", "format": "JSON"},
            headers={"Authorization": f"Bearer {token}"})
        return self.parse(payload)


class CisaKev(Collector):
    name = "kev"
    interval_seconds = 1800
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    @classmethod
    def parse(cls, payload) -> list[Observation]:
        listed = {v["cveID"]: v for v in payload.get("vulnerabilities", [])}
        ts = _hour_now()
        out = []
        for cve in TRACKED_CVES:
            dims = {"cve": cve}
            entry = listed.get(cve)
            if entry is not None and entry.get("dateAdded"):
                dims["dateAdded"] = entry["dateAdded"]
            out.append(Observation(cls.name, "kev_listed", dims, 1.0 if entry else 0.0, ts))
        return out

    async def collect(self, ctx) -> list[Observation]:
        return self.parse(await _fetch(ctx, self.name, self.URL))


def _vtuple(v: str) -> tuple[int, ...] | None:
    try:
        return tuple(int(p) for p in v.split("."))
    except ValueError:
        return None


def is_fixed(version: str) -> bool | None:
    """True if at/above the fixed release of its branch; None if unparseable."""
    t = _vtuple(version)
    if t is None or len(t) < 3:
        return None
    fixed = sorted(_vtuple(f) for f in FIXED_VERSIONS)
    for f in fixed:
        if t[:2] == f[:2]:
            return t >= f
    return t > fixed[-1]  # unlisted branch: newer than all fixed ones is fixed


class ShodanExposure(Collector):
    name = "shodan"
    interval_seconds = 86400
    URL = "https://api.shodan.io/shodan/host/count"

    @classmethod
    def parse(cls, payload) -> list[Observation]:
        fixed = vulnerable = 0
        for f in payload.get("facets", {}).get("version", []):
            verdict = is_fixed(str(f["value"]))
            if verdict is True:
                fixed += f["count"]
            elif verdict is False:
                vulnerable += f["count"]
        ts = _hour_now()
        total = float(payload.get("total", fixed + vulnerable))
        return [
            Observation(cls.name, "php_hosts_fixed", {}, float(fixed), ts),
            Observation(cls.name, "php_hosts_vulnerable", {}, float(vulnerable), ts),
            Observation(cls.name, "php_hosts_total", {}, total, ts),
        ]

    async def collect(self, ctx) -> list[Observation]:
        key = _setting(ctx, "shodan_api_key")
        if not key:
            return []
        payload = await _fetch(ctx, self.name, self.URL,
                               params={"key": key, "query": "product:PHP", "facets": "version:50"})
        return self.parse(payload)
