"""QR에서 읽은 원본 문자열을 검사 가능한 URL 문자열로 정리한다.

app/api/scans.py가 `from app.precheck.payload import InvalidPayload, normalize`로 쓰므로
이 두 이름과 `normalize(raw) -> str` 형태는 바꾸지 않는다.
사이트에는 접속하지 않는다. 문자열만 다룬다.
"""

import unicodedata
from urllib.parse import urlsplit

MAX_URL_LENGTH = 2048
_ALLOWED_SCHEMES = {"http", "https"}
_DEFAULT_PORTS = {"http": 80, "https": 443}


class InvalidPayload(ValueError):
    """검사할 수 없는 입력."""


def normalize(raw: str) -> str:
    if not isinstance(raw, str):
        raise InvalidPayload("입력이 문자열이 아닙니다.")

    text = raw.strip()
    if not text:
        raise InvalidPayload("입력이 비어 있습니다.")
    if len(text) > MAX_URL_LENGTH:
        raise InvalidPayload("입력이 너무 깁니다.")
    for ch in text:
        # 중간 공백, 제어문자, 보이지 않는 서식 문자(방향 전환 등), 역슬래시는 거부한다.
        if ch.isspace() or ch == "\\" or unicodedata.category(ch).startswith("C"):
            raise InvalidPayload("허용되지 않는 문자가 있습니다.")

    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:
        raise InvalidPayload("주소 형식이 올바르지 않습니다.") from exc

    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise InvalidPayload("http 또는 https 주소만 검사할 수 있습니다.")

    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise InvalidPayload("호스트가 없습니다.")
    host = _to_ascii_host(host)

    userinfo, at, _ = parts.netloc.rpartition("@")
    netloc = f"{userinfo}{at}"
    netloc += f"[{host}]" if ":" in host else host
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        netloc += f":{port}"

    url = f"{scheme}://{netloc}{parts.path or '/'}"
    if parts.query:
        url += f"?{parts.query}"
    if parts.fragment:
        url += f"#{parts.fragment}"
    return url


def _to_ascii_host(host: str) -> str:
    """유니코드 도메인을 퓨니코드(xn--)로 통일한다. IP 주소는 그대로 둔다."""
    if ":" in host:  # IPv6
        return host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidPayload("호스트 이름이 올바르지 않습니다.") from exc
