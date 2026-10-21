"""Load persona and signatures from a config directory and hot-reload safely."""

from __future__ import annotations

import contextlib
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Callable

from php2mon.sensor.persona import Persona, parse_persona
from php2mon.sensor.signatures import Evaluator, RuleSet, parse_rules

log = logging.getLogger(__name__)


class ConfigWatcher:
    def __init__(
        self,
        config_dir: Path,
        *,
        state_dir: Path | None = None,
        min_interval: float = 2.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._persona_path = Path(config_dir) / "persona.yaml"
        self._rules_path = Path(config_dir) / "signatures.yaml"
        self._last_good_dir = Path(state_dir) / "last-good" if state_dir is not None else None
        self._min_interval = min_interval
        self._clock = clock
        self._last_check = clock()
        self._stamp: tuple[tuple[int, int, int], tuple[int, int, int]] | None = None
        self._last_error: str | None = None
        self.persona: Persona
        self.evaluator: Evaluator
        try:
            self.reload(force=True)
        except Exception as exc:
            if not self._has_last_good():
                raise
            log.error("config invalid at startup, using last good copy: %s", exc)
            self._load_last_good()

    def _current_stamp(self) -> tuple[tuple[int, int, int], tuple[int, int, int]]:
        def one(path: Path) -> tuple[int, int, int]:
            st = path.stat()
            return (st.st_mtime_ns, st.st_ino, st.st_size)

        return (one(self._persona_path), one(self._rules_path))

    def _log_once(self, message: str) -> None:
        if message != self._last_error:
            log.error(message)
            self._last_error = message

    def _has_last_good(self) -> bool:
        d = self._last_good_dir
        return d is not None and (d / "persona.yaml").is_file() and (d / "signatures.yaml").is_file()

    def _load_last_good(self) -> None:
        d = self._last_good_dir
        assert d is not None
        self._apply(parse_persona((d / "persona.yaml").read_bytes()), parse_rules((d / "signatures.yaml").read_bytes()))
        # Remember the broken files' stamp so only a new push triggers the next load.
        try:
            self._stamp = self._current_stamp()
        except OSError:
            self._stamp = None

    def _save_last_good(self, persona_raw: bytes, rules_raw: bytes) -> None:
        if self._last_good_dir is None:
            return
        try:
            self._last_good_dir.mkdir(parents=True, exist_ok=True)
            for name, data in (("persona.yaml", persona_raw), ("signatures.yaml", rules_raw)):
                fd, tmp = tempfile.mkstemp(dir=self._last_good_dir, prefix=f".{name}.")
                try:
                    with os.fdopen(fd, "wb") as f:
                        f.write(data)
                    os.replace(tmp, self._last_good_dir / name)
                except BaseException:
                    with contextlib.suppress(OSError):
                        os.unlink(tmp)
                    raise
        except Exception as exc:
            log.warning("could not save last good config to %s: %s", self._last_good_dir, exc)

    def _apply(self, persona: Persona, rules: RuleSet) -> None:
        if not hasattr(self, "evaluator"):
            self.evaluator = Evaluator(rules, clock=self._clock)
        else:
            self.evaluator.replace_rules(rules)
        self.persona = persona

    def reload(self, force: bool = False) -> bool:
        stamp = self._current_stamp()
        if not force and stamp == self._stamp:
            return False
        try:
            persona_raw = self._persona_path.read_bytes()
            rules_raw = self._rules_path.read_bytes()
            persona = parse_persona(persona_raw)
            rules = parse_rules(rules_raw)
        except Exception as exc:
            if force:
                raise
            self._log_once(f"config reload failed, keeping previous config: {exc}")
            self._stamp = stamp
            return False
        self._apply(persona, rules)
        self._stamp = stamp
        self._last_error = None
        log.info("config loaded from %s", self._persona_path.parent)
        self._save_last_good(persona_raw, rules_raw)
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
