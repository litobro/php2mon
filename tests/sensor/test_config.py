import logging
import shutil
from pathlib import Path

import pytest

from php2mon.sensor.config import ConfigWatcher

EXAMPLE = Path(__file__).resolve().parents[2] / "config.example"


@pytest.fixture
def cfg(tmp_path):
    shutil.copy(EXAMPLE / "persona.yaml", tmp_path / "persona.yaml")
    shutil.copy(EXAMPLE / "signatures.yaml", tmp_path / "signatures.yaml")
    return tmp_path


def _touch_newer(path: Path):
    import os

    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))


def test_first_load_raises_on_missing_files(tmp_path):
    with pytest.raises(FileNotFoundError):
        ConfigWatcher(tmp_path)


def test_reload_picks_up_persona_change(cfg):
    w = ConfigWatcher(cfg, min_interval=0, clock=lambda: 0.0)
    old = w.persona.server
    text = (cfg / "persona.yaml").read_text().replace(f'server: "{old}"', 'server: "nginx"')
    (cfg / "persona.yaml").write_text(text)
    _touch_newer(cfg / "persona.yaml")
    assert w.reload() is True
    assert w.persona.server == "nginx"


def test_invalid_edit_keeps_last_good_config(cfg, caplog):
    w = ConfigWatcher(cfg, min_interval=0, clock=lambda: 0.0)
    good_server = w.persona.server
    good_eval = w.evaluator
    (cfg / "signatures.yaml").write_text("rules:\n  - id: broken\n")
    _touch_newer(cfg / "signatures.yaml")
    with caplog.at_level(logging.ERROR):
        assert w.reload() is False
    assert w.persona.server == good_server
    assert w.evaluator is good_eval
    assert "keeping previous" in caplog.text
    # does not retry on every call until the file changes again
    assert w.reload() is False


def test_maybe_reload_rate_limits_stat_calls(cfg):
    now = [0.0]
    w = ConfigWatcher(cfg, min_interval=2.0, clock=lambda: now[0])
    (cfg / "persona.yaml").write_text(
        (cfg / "persona.yaml").read_text().replace('x_powered_by: "PHP/8.3.0"', 'x_powered_by: "PHP/7.4.0"')
    )
    _touch_newer(cfg / "persona.yaml")
    w.maybe_reload()
    assert w.persona.x_powered_by == "PHP/8.3.0"  # within min_interval of construction
    now[0] += 2.5
    w.maybe_reload()
    assert w.persona.x_powered_by == "PHP/7.4.0"
