"""The decoy's outward identity, loaded from persona.yaml."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class MemoryTrigger(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_body_bytes: int = 2 * 1024 * 1024
    multipart_only: bool = True


class Persona(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server: str
    x_powered_by: str
    server_name: str = "localhost"
    session_cookie: str = "PHPSESSID"
    pages: dict[str, str]
    not_found: str
    fatal: str
    memory_trigger: MemoryTrigger = Field(default_factory=MemoryTrigger)

    @field_validator("server", "x_powered_by", "server_name")
    @classmethod
    def _latin1(cls, value: str) -> str:
        # These go out as raw header bytes or into the 404 page; reject them at load, not per request.
        try:
            value.encode("latin-1")
        except UnicodeEncodeError:
            raise ValueError("must be encodable as latin-1") from None
        return value


def parse_persona(data: bytes | str) -> Persona:
    return Persona.model_validate(yaml.safe_load(data))


def load_persona(path: Path) -> Persona:
    return parse_persona(path.read_text())
