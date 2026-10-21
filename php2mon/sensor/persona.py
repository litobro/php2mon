"""The decoy's outward identity, loaded from persona.yaml."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class MemoryTrigger(BaseModel):
    min_body_bytes: int = 2 * 1024 * 1024
    multipart_only: bool = True


class Persona(BaseModel):
    server: str
    x_powered_by: str
    session_cookie: str = "PHPSESSID"
    pages: dict[str, str]
    not_found: str
    fatal: str
    memory_trigger: MemoryTrigger = Field(default_factory=MemoryTrigger)


def load_persona(path: Path) -> Persona:
    return Persona.model_validate(yaml.safe_load(path.read_text()))
