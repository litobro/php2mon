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
        self._stamp: tuple[tuple[int, int, int], tuple[int, int, int]] | None = None
        self._last_error: str | None = None
        self.persona: Persona
        self.evaluator: Evaluator
        self.reload(force=True)

    def _current_stamp(self) -> tuple[tuple[int, int, int], tuple[int, int, int]]:
        def one(path: Path) -> tuple[int, int, int]:
            st = path.stat()
            return (st.st_mtime_ns, st.st_ino, st.st_size)

        return (one(self._persona_path), one(self._rules_path))

    def _log_once(self, message: str) -> None:
        if message != self._last_error:
            log.error(message)
            self._last_error = message

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
            self._log_once(f"config reload failed, keeping previous config: {exc}")
            self._stamp = stamp
            return False
        if self._stamp is None:
            self.evaluator = Evaluator(rules, clock=self._clock)
        else:
            self.evaluator.replace_rules(rules)
        self.persona = persona
        self._stamp = stamp
        self._last_error = None
        log.info("config loaded from %s", self._persona_path.parent)
        return True

    def maybe_reload(self) -> None:
        now = self._clock()
        if now - self._last_check < self._min_interval:
            return
        self._last_check = now
        try:
            self.reload()
        except Exception as exc:
            self._log_once(f"config reload failed, keeping previous config: {exc}")
