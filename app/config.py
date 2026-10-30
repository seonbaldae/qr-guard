"""Explicit environment settings; no .env files or secrets are loaded."""

import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.precheck.payload import normalize


def origin(url: str) -> str:
    parts = urlsplit(normalize(url))
    if parts.username is not None or parts.password is not None:
        raise ValueError("Credentials are not allowed in Worker target URLs")
    return f"{parts.scheme}://{parts.netloc}"


def configured_origin(value: str) -> str:
    parts = urlsplit(normalize(value))
    if parts.path != "/" or parts.query or parts.fragment or "*" in parts.netloc:
        raise ValueError("Configure exact HTTP(S) origins, without paths or wildcards")
    return origin(value)


@dataclass(frozen=True)
class Settings:
    worker_url: str | None = None
    worker_container: str | None = None
    demo_origins: tuple[str, ...] = ()
    cors_origins: tuple[str, ...] = ()
    worker_egress_verified: bool = False
    public_preview: bool = False
    worker_timeout_ms: int = 20000
    max_scans: int = 100
    max_worker_concurrency: int = 2

    def __post_init__(self):
        if self.worker_container and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.worker_container):
            raise ValueError("Invalid Worker container name")
        if self.worker_container and self.worker_url:
            raise ValueError("Configure either Worker container or Worker URL")
        if self.worker_url:
            configured_origin(self.worker_url)
        for value in (*self.demo_origins, *self.cors_origins):
            configured_origin(value)
        if min(self.worker_timeout_ms, self.max_scans, self.max_worker_concurrency) <= 0:
            raise ValueError("Timeout and capacity settings must be positive")

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            worker_url=os.getenv("QR_GUARD_WORKER_URL") or None,
            worker_container=os.getenv("QR_GUARD_WORKER_CONTAINER") or None,
            demo_origins=tuple(filter(None, (
                value.strip() for value in os.getenv("QR_GUARD_DEMO_ORIGINS", "").split(",")
            ))),
            worker_egress_verified=os.getenv("QR_GUARD_WORKER_EGRESS_VERIFIED") == "true",
            public_preview=os.getenv("QR_GUARD_PUBLIC_PREVIEW") == "true",
            max_scans=int(os.getenv("QR_GUARD_MAX_SCANS", "100")),
            max_worker_concurrency=int(os.getenv("QR_GUARD_WORKER_CONCURRENCY", "2")),
            cors_origins=tuple(filter(None, (
                value.strip() for value in os.getenv("QR_GUARD_CORS_ORIGINS", "").split(",")
            ))),
        )
