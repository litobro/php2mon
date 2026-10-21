"""Fixed-window per-IP counter to bound disk use under floods."""

from __future__ import annotations

import ipaddress
import time
from typing import Callable

MAX_BUCKETS = 100_000


def _key(ip: str) -> str:
    """Key IPv6 by its /64 so one client cannot dodge the limit by rotating addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 4:
        return ip
    return str(ipaddress.ip_network(f"{ip}/64", strict=False))


class RateLimiter:
    def __init__(self, per_minute: int = 120, clock: Callable[[], float] = time.monotonic) -> None:
        self._limit = per_minute
        self._clock = clock
        self._buckets: dict[str, tuple[float, int]] = {}
        self._calls = 0

    def allow(self, ip: str) -> bool:
        now = self._clock()
        key = _key(ip)
        if key not in self._buckets and len(self._buckets) >= MAX_BUCKETS:
            self._prune(now)
            while len(self._buckets) >= MAX_BUCKETS:
                del self._buckets[next(iter(self._buckets))]
        start, count = self._buckets.get(key, (now, 0))
        if now - start >= 60:
            start, count = now, 0
        count += 1
        self._buckets[key] = (start, count)
        self._calls += 1
        if self._calls % 10_000 == 0:
            self._prune(now)
        return count <= self._limit

    def _prune(self, now: float) -> None:
        self._buckets = {ip: (s, c) for ip, (s, c) in self._buckets.items() if now - s < 60}
