"""Fixed-window per-IP counter to bound disk use under floods."""

from __future__ import annotations

import time
from typing import Callable


class RateLimiter:
    def __init__(self, per_minute: int = 120, clock: Callable[[], float] = time.monotonic) -> None:
        self._limit = per_minute
        self._clock = clock
        self._buckets: dict[str, tuple[float, int]] = {}
        self._calls = 0

    def allow(self, ip: str) -> bool:
        now = self._clock()
        start, count = self._buckets.get(ip, (now, 0))
        if now - start >= 60:
            start, count = now, 0
        count += 1
        self._buckets[ip] = (start, count)
        self._calls += 1
        if self._calls % 10_000 == 0:
            self._prune(now)
        return count <= self._limit

    def _prune(self, now: float) -> None:
        self._buckets = {ip: (s, c) for ip, (s, c) in self._buckets.items() if now - s < 60}
