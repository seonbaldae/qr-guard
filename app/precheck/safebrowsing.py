"""Google Safe Browsing API(v4 Lookup, threatMatches:find)로 URL의 위협 여부를 조회한다.

사용 조건(확인일 2026-10-31, developers.google.com/safe-browsing):
- 비상업적 용도 전용. 상업적 사용은 별도 계약(Web Risk)이 필요하다.
- 위험으로 경고하려면 최근 30분 안에 받은 결과여야 한다. 그래서 결과를 저장하지 않고 매번 조회한다.
- 사용자에게 "Google 기술로 보호한다"고 알린다면 출처 표시와 정확성 비보증 고지가 필요하다. (화면은 A, 프론트 담당)

개인정보: Lookup API는 URL을 Google에 보낸다. 그래서 보내기 전에 쿼리, 프래그먼트,
아이디/비밀번호를 제거하고 스킴+호스트+경로만 보낸다. Evidence와 로그에도 URL 원문을 넣지 않는다.

API 키는 환경변수 SAFE_BROWSING_API_KEY에서 읽고, 없으면 저장소 루트의 .env 파일에서 읽는다.
키는 요청 주소(?key=)에 들어가므로 오류 메시지를 결과에 옮기지 않는다.
키가 없거나 조회에 실패하면 "깨끗함"이 아니라 "확인 못 함"(status=failed, matched=None)이다.
"""

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import requests

from app.precheck.payload import InvalidPayload, normalize
from app.precheck.schema import Evidence, ProviderResult, Signal

PROVIDER_NAME = "google-safebrowsing"
API_KEY_ENV = "SAFE_BROWSING_API_KEY"
ENV_FILE = Path(__file__).resolve().parents[2] / ".env"
ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
_CLIENT = {"clientId": "qr-guard-precheck", "clientVersion": "0.1"}
_THREAT_TYPES = ["SOCIAL_ENGINEERING", "MALWARE"]
_TIMEOUT_SECONDS = 5

Sender = Callable[[dict[str, Any], str], tuple[int, Any]]


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
        body = _request_body(url)
    except InvalidPayload:
        return _failed()

    try:
        status, payload = (send or _send)(body, key)
    except requests.RequestException:
        return _failed()  # 오류 문장에 키가 들어 있을 수 있어 옮기지 않는다.
    if status != 200 or not isinstance(payload, dict):
        return _failed()

    matches = payload.get("matches", [])
    if not isinstance(matches, list) or not all(isinstance(m, dict) for m in matches):
        return _failed()

    checked_at = _iso(now or datetime.now(timezone.utc))
    if not matches:
        return SafeBrowsingCheck(_provider("checked", False, checked_at))

    threat_types = sorted(
        {m["threatType"] for m in matches if _is_threat_type(m.get("threatType"))}
    )
    evidence = Evidence(
        id="ev-safebrowsing",
        kind="threat_feed_match",
        source=PROVIDER_NAME,
        observedAt=checked_at,
        summary="Google Safe Browsing 위협 목록과 일치합니다.",
        data={"threatTypes": ",".join(threat_types)} if threat_types else None,
    )
    signal = Signal(
        id="sig-threat_feed_match-safebrowsing",
        kind="threat_feed_match",
        severity="high",
        summary="Google Safe Browsing 위협 목록에 일치합니다.",
        source=PROVIDER_NAME,
        evidenceIds=[evidence.id],
    )
    return SafeBrowsingCheck(_provider("checked", True, checked_at), [signal], [evidence])


def _load_api_key() -> str:
    """환경변수가 우선이고, 없으면 .env 파일의 SAFE_BROWSING_API_KEY=값 줄을 읽는다."""
    from_env = os.environ.get(API_KEY_ENV, "").strip()
    if from_env:
        return from_env
    try:
        lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    for line in lines:
        name, sep, value = line.partition("=")
        if sep and name.strip() == API_KEY_ENV:
            return value.strip().strip("\"'")
    return ""


def _request_body(url: str) -> dict[str, Any]:
    return {
        "client": _CLIENT,
        "threatInfo": {
            "threatTypes": _THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": _url_to_send(url)}],
        },
    }


def _url_to_send(url: str) -> str:
    """Google에 보낼 URL. 쿼리, 프래그먼트, 아이디/비밀번호는 보내지 않는다."""
    parts = urlsplit(normalize(url))
    host_port = parts.netloc.rpartition("@")[2]
    return f"{parts.scheme}://{host_port}{parts.path}"


def _send(body: dict[str, Any], api_key: str) -> tuple[int, Any]:
    response = requests.post(
        ENDPOINT, params={"key": api_key}, json=body, timeout=_TIMEOUT_SECONDS
    )
    try:
        return response.status_code, response.json()
    except ValueError:
        return response.status_code, None


def _is_threat_type(value: Any) -> bool:
    return isinstance(value, str) and value.isupper() and value.replace("_", "").isalpha()


def _failed() -> SafeBrowsingCheck:
    return SafeBrowsingCheck(_provider("failed", None, None))


def _provider(status: str, matched: bool | None, checked_at: str | None) -> ProviderResult:
    return ProviderResult(name=PROVIDER_NAME, status=status, matched=matched, checkedAt=checked_at)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
