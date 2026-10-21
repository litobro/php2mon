"""Create least-privilege DB roles and set their passwords."""

from __future__ import annotations

from pathlib import Path

ROLES_PATH = Path(__file__).with_name("roles.sql")

_ROLES = ("php2mon_sensor", "php2mon_collector", "php2mon_dashboard")


def _lit(s: str) -> str:
    """Quote a string as a SQL literal (ALTER ROLE cannot take bind parameters)."""
    return "'" + s.replace("'", "''") + "'"


async def apply_roles(pool, *, sensor_pw: str, collector_pw: str, dashboard_pw: str) -> None:
    async with pool.acquire() as conn:
        await conn.execute(ROLES_PATH.read_text())
        for role, pw in zip(_ROLES, (sensor_pw, collector_pw, dashboard_pw), strict=True):
            assert role in _ROLES  # role names are fixed literals, never caller input
            await conn.execute(f"ALTER ROLE {role} WITH PASSWORD {_lit(pw)}")
