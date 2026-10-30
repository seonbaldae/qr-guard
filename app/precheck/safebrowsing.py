"""Google Safe Browsing v5 sends normalized URLs (including queries) to Google."""

from collections import OrderedDict
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
import hmac
import json
import os
from pathlib import Path
import re
import threading
import time
from typing import Any, Callable

import httpx

from app.precheck.payload import InvalidPayload, normalize
from app.precheck.schema import Evidence, ProviderResult, Signal

PROVIDER_NAME = "google_safe_browsing"
API_KEY_ENV = "GOOGLE_SAFE_BROWSING_API_KEY"
LEGACY_API_KEY_ENV = "SAFE_BROWSING_API_KEY"
ENV_FILE = Path(__file__).resolve().parents[2] / ".env"
ENDPOINT = "https://safebrowsing.googleapis.com/v5/urls:search"
_TIMEOUT_SECONDS = 5

Sender = Callable[[str, str], tuple[int, Any]]
_CACHE = OrderedDict()
_PENDING: set[bytes] = set()
_LOCK = threading.Lock()
_SECRET = os.urandom(32)
_CACHE_CAPACITY = 512


@dataclass(frozen=True)
class SafeBrowsingCheck:
    provider: ProviderResult
    signals: list[Signal] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)


def check_safe_browsing(
    url: str,
    *,
    api_key: str | None = None,
    send: Sender | None = None,
    now: datetime | None = None,
) -> SafeBrowsingCheck:
    key = api_key if api_key is not None else _load_api_key()
    if not key.strip():
        return _failed()
    try:
        body = normalize(url)
    except InvalidPayload:
        return _failed()

    fingerprint = hmac.digest(_SECRET, (key + "\0" + body).encode(), "sha256")
    with _LOCK:
        moment = Decimal(str(time.monotonic()))
        for cached_key, entry in list(_CACHE.items()):
            if moment >= entry[0]:
                del _CACHE[cached_key]
        entry = _CACHE.get(fingerprint)
        if entry:
            _CACHE.move_to_end(fingerprint)
            return deepcopy(entry[1])
        # Preserve unexpired Google responses rather than evicting and re-querying.
        if fingerprint in _PENDING or len(_CACHE.keys() | _PENDING) >= _CACHE_CAPACITY:
            return _failed()
        _PENDING.add(fingerprint)
    try:
        return _lookup_uncached(body, key, send, now, fingerprint)
    finally:
        with _LOCK:
            _PENDING.discard(fingerprint)


def _lookup_uncached(
    body: str, key: str, send: Sender | None, now: datetime | None, fingerprint: bytes,
) -> SafeBrowsingCheck:
    try:
        status, payload = (send or _send)(body, key)
    except (httpx.HTTPError, ValueError):
        return _failed()  # 오류 문장에 키가 들어 있을 수 있어 옮기지 않는다.
    if status != 200 or not isinstance(payload, dict):
        return _failed()

    duration = payload.get("cacheDuration", "0s")
    if not isinstance(duration, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]{1,9})?s", duration):
        return _failed()
    ttl = Decimal(duration[:-1])
    matches = payload.get("threats", [])
    if not isinstance(matches, list) or not all(isinstance(m, dict) for m in matches):
        return _failed()

    for match in matches:
        invalid_url = "url" in match and not isinstance(match["url"], str)
        types = match.get("threatTypes", [])
        if invalid_url or not isinstance(types, list) or not all(_is_threat_type(item) for item in types):
            return _failed()
    checked_at = _iso(now or datetime.now(timezone.utc))
    if not matches:
        return _store(fingerprint, ttl, SafeBrowsingCheck(_provider("checked", False, checked_at)))

    threat_types = sorted(
        {t for m in matches for t in m.get("threatTypes", []) if t in {"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"}}
    )
    evidence = Evidence(
        id="ev-safebrowsing",
        kind="known_threat_match",
        source=PROVIDER_NAME,
        observedAt=checked_at,
        summary="Google Safe Browsing 위협 목록과 일치합니다.",
        data={"threatTypes": ",".join(threat_types)} if threat_types else None,
    )
    signal = Signal(
        id="sig-known_threat_match-safebrowsing",
        kind="known_threat_match",
        severity="high",
        summary="Google Safe Browsing 위협 목록에 일치합니다.",
        source=PROVIDER_NAME,
        evidenceIds=[evidence.id],
    )
    return _store(fingerprint, ttl, SafeBrowsingCheck(_provider("checked", True, checked_at), [signal], [evidence]))


def _store(fingerprint: bytes, ttl: Decimal, result: SafeBrowsingCheck) -> SafeBrowsingCheck:
    if ttl > 0:
        with _LOCK:
            _CACHE[fingerprint] = (Decimal(str(time.monotonic())) + ttl, deepcopy(result))
            _CACHE.move_to_end(fingerprint)
    return result


def _load_api_key() -> str:
    for name in (API_KEY_ENV, LEGACY_API_KEY_ENV):
        if name in os.environ:
            return os.environ[name].strip()
    try:
        lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    values = {}
    for line in lines:
        name, sep, value = line.partition("=")
        if sep:
            values[name.strip()] = value.strip().strip("\"'")
    return values.get(API_KEY_ENV, values.get(LEGACY_API_KEY_ENV, ""))


def _send(url: str, api_key: str) -> tuple[int, Any]:
    request = httpx.Request("GET", ENDPOINT, params={"urls": url},
                            headers={"X-Goog-Api-Key": api_key},
                            extensions={"timeout": dict.fromkeys(("connect", "read", "write", "pool"), _TIMEOUT_SECONDS)})
    # Use transport directly: Client logs the complete query at INFO level.
    with httpx.HTTPTransport(retries=0, trust_env=False) as transport:
        response = transport.handle_request(request)
        try:
            data = bytearray()
            for chunk in response.iter_bytes():
                data.extend(chunk)
                if len(data) > 1024 * 1024:
                    return response.status_code, None
            try:
                return response.status_code, json.loads(data)
            except (ValueError, UnicodeDecodeError):
                return response.status_code, None
        finally:
            response.close()


def _is_threat_type(value: Any) -> bool:
    return isinstance(value, str) and value.isupper() and value.replace("_", "").isalpha()


def _failed() -> SafeBrowsingCheck:
    return SafeBrowsingCheck(_provider("failed", None, None))


def _provider(status: str, matched: bool | None, checked_at: str | None) -> ProviderResult:
    return ProviderResult(name=PROVIDER_NAME, status=status, matched=matched, checkedAt=checked_at)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
