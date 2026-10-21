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


def test_maybe_reload_survives_missing_file(cfg, caplog):
    w = ConfigWatcher(cfg, min_interval=0, clock=lambda: 0.0)
    old = w.persona.server
    (cfg / "signatures.yaml").unlink()
    with caplog.at_level(logging.ERROR):
        w.maybe_reload()
        w.maybe_reload()
        w.maybe_reload()
    assert w.persona.server == old
    assert caplog.text.count("keeping previous") == 1


def test_maybe_reload_survives_unreadable_file(cfg, caplog, monkeypatch):
    w = ConfigWatcher(cfg, min_interval=0, clock=lambda: 0.0)

    def boom(self, *a, **k):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "stat", boom)
    with caplog.at_level(logging.ERROR):
        w.maybe_reload()
    assert "denied" in caplog.text


def test_good_load_writes_last_good_copies(cfg, tmp_path_factory):
    state = tmp_path_factory.mktemp("state")
    ConfigWatcher(cfg, state_dir=state)
    for name in ("persona.yaml", "signatures.yaml"):
        assert (state / "last-good" / name).read_bytes() == (cfg / name).read_bytes()


def test_reload_refreshes_last_good_copies(cfg, tmp_path_factory):
    state = tmp_path_factory.mktemp("state")
    w = ConfigWatcher(cfg, state_dir=state, min_interval=0, clock=lambda: 0.0)
    text = (cfg / "persona.yaml").read_text().replace(f'server: "{w.persona.server}"', 'server: "nginx"')
    (cfg / "persona.yaml").write_text(text)
    _touch_newer(cfg / "persona.yaml")
    assert w.reload() is True
    assert (state / "last-good" / "persona.yaml").read_text() == text


def test_invalid_config_at_startup_falls_back_to_last_good(cfg, tmp_path_factory, caplog):
    state = tmp_path_factory.mktemp("state")
    first = ConfigWatcher(cfg, state_dir=state)
    good_ids = [r.id for r in first.evaluator._rules]
    (cfg / "signatures.yaml").write_text("rules:\n  - id: broken\n")
    with caplog.at_level(logging.ERROR):
        w = ConfigWatcher(cfg, state_dir=state, min_interval=0, clock=lambda: 0.0)
    assert [r.id for r in w.evaluator._rules] == good_ids
    assert "using last good copy" in caplog.text
    # the broken file must not overwrite the last good copy
    assert (state / "last-good" / "signatures.yaml").read_bytes() == (EXAMPLE / "signatures.yaml").read_bytes()
    # a fixed push is still picked up from config_dir
    shutil.copy(EXAMPLE / "signatures.yaml", cfg / "signatures.yaml")
    text = (cfg / "persona.yaml").read_text().replace(f'server: "{w.persona.server}"', 'server: "nginx"')
    (cfg / "persona.yaml").write_text(text)
    _touch_newer(cfg / "persona.yaml")
    assert w.reload() is True
    assert w.persona.server == "nginx"


def test_invalid_config_at_startup_without_last_good_raises(cfg, tmp_path_factory):
    state = tmp_path_factory.mktemp("state")
    (cfg / "signatures.yaml").write_text("rules:\n  - id: broken\n")
    with pytest.raises(Exception):
        ConfigWatcher(cfg, state_dir=state)
    assert not (state / "last-good" / "signatures.yaml").exists()


def test_unwritable_state_dir_only_warns(cfg, tmp_path, caplog):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    with caplog.at_level(logging.WARNING):
        w = ConfigWatcher(cfg, state_dir=blocker)
    assert w.persona.server
    assert any(r.levelno == logging.WARNING for r in caplog.records)
