"""Turn a raw HTTP request into a HitRecord: the single row the sensor logs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

HEADER_VALUE_CAP = 2048
BODY_HEAD_CAP = 4096

_BOUNDARY_RE = re.compile(r'boundary="?([^";,\s]+)"?', re.IGNORECASE)


@dataclass
class HitRecord:
    ts: datetime
    src_ip: str
    method: str
    path: str
    host: str | None
    user_agent: str | None
    content_type: str | None
    body_bytes: int
    multipart_parts: int
    sess_len: int
    header_names: list[str]
    headers: dict[str, str]
    body_head: bytes
    resp_status: int = 0
    signatures: list[str] = field(default_factory=list)
    country: str | None = None
    asn: int | None = None
    asn_name: str | None = None
    detail_kept: bool = True
    query: str = ""

    def to_detail(self) -> dict:
        return {
            "query": self.query,
            "headers": self.headers,
            "body_head": self.body_head.decode("utf-8", "replace"),
        }


class MultipartCounter:
    """Counts multipart parts by boundary markers while a body streams past."""

    def __init__(self, boundary: str) -> None:
        self._marker = b"--" + boundary.encode("ascii", "replace") + b"\r\n"
        self._tail = b""
        self.parts = 0

    @classmethod
    def from_content_type(cls, content_type: str | None) -> "MultipartCounter | None":
        if not content_type or not content_type.lower().startswith("multipart/"):
            return None
        match = _BOUNDARY_RE.search(content_type)
        return cls(match.group(1)) if match else None

    def feed(self, chunk: bytes) -> None:
        data = self._tail + chunk
        self.parts += data.count(self._marker)
        keep = len(self._marker) - 1
        self._tail = data[-keep:] if keep else b""


def session_length(cookie_header: str | None, name: str) -> int:
    if not cookie_header:
        return 0
    for part in cookie_header.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep and key.strip() == name:
            return len(value.strip())
    return 0


def build_hit(
    *,
    src_ip: str,
    method: str,
    path: str,
    headers: Iterable[tuple[str, str]],
    body_bytes: int,
    multipart_parts: int,
    body_head: bytes,
    query: str = "",
    session_cookie: str = "PHPSESSID",
    now: datetime | None = None,
) -> HitRecord:
    names: list[str] = []
    hdrs: dict[str, str] = {}
    raw: dict[str, str] = {}
    for key, value in headers:
        lower = key.lower()
        names.append(lower)
        raw[lower] = value
        hdrs[lower] = value[:HEADER_VALUE_CAP]
    return HitRecord(
        ts=now or datetime.now(timezone.utc),
        src_ip=src_ip,
        method=method.upper(),
        path=path,
        host=hdrs.get("host"),
        user_agent=hdrs.get("user-agent"),
        content_type=hdrs.get("content-type"),
        body_bytes=body_bytes,
        multipart_parts=multipart_parts,
        sess_len=session_length(raw.get("cookie"), session_cookie),
        header_names=names,
        headers=hdrs,
        body_head=body_head[:BODY_HEAD_CAP],
        query=query[:HEADER_VALUE_CAP],
    )
