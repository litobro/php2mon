"""Collector base types."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Observation:
    source: str
    metric: str
    dimensions: dict
    value: float
    ts: datetime


class Collector:
    name: str = "collector"
    interval_seconds: int = 3600
    def __init__(self) -> None:
        self.consecutive_failures = 0
    async def collect(self, ctx) -> list[Observation]:
        raise NotImplementedError
