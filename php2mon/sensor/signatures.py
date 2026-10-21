"""Signature rules: classify a HitRecord into zero or more rule ids."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from enum import StrEnum
from pathlib import Path
from typing import Callable

import yaml
from pydantic import BaseModel

from php2mon.sensor.hits import HitRecord


class Confidence(StrEnum):
    probe = "probe"
    likely = "likely"
    exploit = "exploit"


class Conditions(BaseModel):
    method: str | None = None
    path_prefix: str | None = None
    path_contains: str | None = None
    content_type_prefix: str | None = None
    body_bytes_min: int | None = None
    multipart_parts_min: int | None = None
    sess_len_min: int | None = None
    resp_status: int | None = None
    user_agent_contains: str | None = None
    header_present: str | None = None
    repeats_min: int | None = None
    window_seconds: int = 600


class Rule(BaseModel):
    id: str
    label: str
    confidence: Confidence
    when: Conditions


class RuleSet(BaseModel):
    rules: list[Rule]


def load_rules(path: Path) -> RuleSet:
    return RuleSet.model_validate(yaml.safe_load(path.read_text()))


def _static_match(c: Conditions, hit: HitRecord) -> bool:
    ct = (hit.content_type or "").lower()
    ua = hit.user_agent or ""
    checks = [
        c.method is None or hit.method == c.method.upper(),
        c.path_prefix is None or hit.path.startswith(c.path_prefix),
        c.path_contains is None or c.path_contains in hit.path,
        c.content_type_prefix is None or ct.startswith(c.content_type_prefix.lower()),
        c.body_bytes_min is None or hit.body_bytes >= c.body_bytes_min,
        c.multipart_parts_min is None or hit.multipart_parts >= c.multipart_parts_min,
        c.sess_len_min is None or hit.sess_len >= c.sess_len_min,
        c.resp_status is None or hit.resp_status == c.resp_status,
        c.user_agent_contains is None or c.user_agent_contains in ua,
        c.header_present is None or c.header_present.lower() in hit.header_names,
    ]
    return all(checks)


class Evaluator:
    def __init__(self, ruleset: RuleSet, clock: Callable[[], float] = time.monotonic) -> None:
        self._rules = ruleset.rules
        self._clock = clock
        self._history: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def replace_rules(self, ruleset: RuleSet) -> None:
        self._rules = ruleset.rules

    def _repeat_match(self, rule: Rule, hit: HitRecord) -> bool:
        c = rule.when
        if c.repeats_min is None:
            return True
        now = self._clock()
        bucket = self._history[(rule.id, hit.src_ip)]
        bucket.append(now)
        while bucket and now - bucket[0] > c.window_seconds:
            bucket.popleft()
        return len(bucket) >= c.repeats_min

    def evaluate(self, hit: HitRecord) -> list[str]:
        matched: list[str] = []
        for rule in self._rules:
            if _static_match(rule.when, hit) and self._repeat_match(rule, hit):
                matched.append(rule.id)
        return matched
