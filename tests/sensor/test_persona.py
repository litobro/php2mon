from pathlib import Path

import pytest
from pydantic import ValidationError

from php2mon.sensor.persona import load_persona

EXAMPLE = Path(__file__).resolve().parents[2] / "config.example" / "persona.yaml"


def test_example_persona_loads():
    persona = load_persona(EXAMPLE)
    assert persona.server
    assert persona.x_powered_by.startswith("PHP/")
    assert "/" in persona.pages
    assert "{bytes}" in persona.fatal
    assert persona.memory_trigger.min_body_bytes > 0


def test_missing_field_rejected(tmp_path):
    bad = tmp_path / "persona.yaml"
    bad.write_text("server: Apache\n")
    with pytest.raises(ValidationError):
        load_persona(bad)
