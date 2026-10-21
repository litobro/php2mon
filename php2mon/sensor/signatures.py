"""Signature rules: classify a HitRecord into zero or more rule ids."""

from __future__ import annotations

import time
from collections import deque
from enum import StrEnum
from pathlib import Path
from typing import Callable
from urllib.parse import unquote

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from php2mon.sensor.hits import HitRecord

MAX_HISTORY_KEYS = 100_000
SWEEP_EVERY = 1_000


class Confidence(StrEnum):
    probe = "probe"
    likely = "likely"
    exploit = "exploit"


class Conditions(BaseModel):
    model_config = ConfigDict(extra="forbid")

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
    repeats_min: int | None = Field(default=None, ge=1)
    window_seconds: int = Field(default=600, ge=1)


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    label: str
    confidence: Confidence
    when: Conditions


class RuleSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: list[Rule]

    @field_validator("rules")
    @classmethod
    def _unique_ids(cls, rules: list[Rule]) -> list[Rule]:
        seen: set[str] = set()
        for rule in rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id: {rule.id}")
            seen.add(rule.id)
        return rules


def parse_rules(data: bytes | str) -> RuleSet:
    return RuleSet.model_validate(yaml.safe_load(data))


def load_rules(path: Path) -> RuleSet:
    return parse_rules(path.read_text())


def _norm_path(path: str) -> str:
    return unquote(path).lower()


def _static_match(c: Conditions, hit: HitRecord) -> bool:
    ct = (hit.content_type or "").lower()
    ua = (hit.user_agent or "").lower()
    path = _norm_path(hit.path)
    checks = [
        c.method is None or hit.method == c.method.upper(),
        c.path_prefix is None or path.startswith(c.path_prefix.lower()),
        c.path_contains is None or c.path_contains.lower() in path,
        c.content_type_prefix is None or ct.startswith(c.content_type_prefix.lower()),
        c.body_bytes_min is None or hit.body_bytes >= c.body_bytes_min,
        c.multipart_parts_min is None or hit.multipart_parts >= c.multipart_parts_min,
        c.sess_len_min is None or hit.sess_len >= c.sess_len_min,
        c.resp_status is None or hit.resp_status == c.resp_status,
        c.user_agent_contains is None or c.user_agent_contains.lower() in ua,
        c.header_present is None or c.header_present.lower() in hit.header_names,
    ]
    return all(checks)


class Evaluator:
    def __init__(self, ruleset: RuleSet, clock: Callable[[], float] = time.monotonic) -> None:
        self._rules = ruleset.rules
        self._clock = clock
        self._history: dict[tuple[str, str], deque[float]] = {}
        self._calls = 0

    def replace_rules(self, ruleset: RuleSet) -> None:
        self._rules = ruleset.rules
        self._sweep(self._clock())

    def _repeat_match(self, rule: Rule, hit: HitRecord) -> bool:
        c = rule.when
        if c.repeats_min is None:
            return True
        now = self._clock()
        key = (rule.id, hit.src_ip)
        bucket = self._history.setdefault(key, deque())
        bucket.append(now)
        while bucket and now - bucket[0] > c.window_seconds:
            bucket.popleft()
        if not bucket:
            del self._history[key]
            return False
        return len(bucket) >= c.repeats_min

    def _sweep(self, now: float) -> None:
        windows = {rule.id: rule.when.window_seconds for rule in self._rules}
        max_window = max(windows.values(), default=0)
        for key in list(self._history):
            rule_id, _ = key
            bucket = self._history[key]
            if rule_id not in windows or not bucket or now - bucket[-1] > max_window:
                del self._history[key]
        if len(self._history) > MAX_HISTORY_KEYS:
            excess = len(self._history) - MAX_HISTORY_KEYS
            for key in list(self._history)[:excess]:
                del self._history[key]

    def evaluate(self, hit: HitRecord) -> list[str]:
        self._calls += 1
        if self._calls % SWEEP_EVERY == 0:
            self._sweep(self._clock())
        matched: list[str] = []
        for rule in self._rules:
            if _static_match(rule.when, hit) and self._repeat_match(rule, hit):
                matched.append(rule.id)
        return matched
