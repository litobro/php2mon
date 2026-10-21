"""Load persona and signatures from a config directory and hot-reload safely."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Callable

from php2mon.sensor.persona import Persona, load_persona
from php2mon.sensor.signatures import Evaluator, load_rules

log = logging.getLogger(__name__)


class ConfigWatcher:
    def __init__(
        self,
        config_dir: Path,
        *,
        min_interval: float = 2.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._persona_path = Path(config_dir) / "persona.yaml"
        self._rules_path = Path(config_dir) / "signatures.yaml"
        self._min_interval = min_interval
        self._clock = clock
        self._last_check = clock()
        self._stamp: tuple[int, int] | None = None
        self.persona: Persona
        self.evaluator: Evaluator
        self.reload(force=True)

    def _current_stamp(self) -> tuple[int, int]:
        return (self._persona_path.stat().st_mtime_ns, self._rules_path.stat().st_mtime_ns)

    def reload(self, force: bool = False) -> bool:
        stamp = self._current_stamp()
        if not force and stamp == self._stamp:
            return False
        try:
            persona = load_persona(self._persona_path)
            rules = load_rules(self._rules_path)
        except Exception as exc:
            if force:
                raise
            log.error("config reload failed, keeping previous config: %s", exc)
            self._stamp = stamp
            return False
        self.persona = persona
        if self._stamp is None:
            self.evaluator = Evaluator(rules, clock=self._clock)
        else:
            self.evaluator.replace_rules(rules)
        self._stamp = stamp
        log.info("config loaded from %s", self._persona_path.parent)
        return True

    def maybe_reload(self) -> None:
        now = self._clock()
        if now - self._last_check < self._min_interval:
            return
        self._last_check = now
        try:
            self.reload()
        except FileNotFoundError as exc:
            log.error("config file missing, keeping previous config: %s", exc)
