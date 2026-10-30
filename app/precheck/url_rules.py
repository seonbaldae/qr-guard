"""정규화된 URL을 분해하고 URL 구조만으로 알 수 있는 신호를 만든다.

사이트에는 접속하지 않는다. 신호 kind와 severity는 A와 합의하기 전의 "제안"이다.
Evidence와 로그에 쿼리, 토큰, 개인정보 원문을 넣지 않는다.
"""

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

import tldextract

from app.precheck.payload import normalize
from app.precheck.schema import Signal

# 오프라인 스냅샷만 사용한다. 실행 중에 Public Suffix List를 내려받지 않는다.
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_SOURCE = "local-rule"
_DEEP_SUBDOMAIN_LABELS = 3
_HEX_IP = re.compile(r"0x[0-9a-f]+", re.IGNORECASE)

_LONG_URL_LENGTH = 200

# 위험 TLD 목록은 공신력 있는 출처를 확인한 뒤 채운다. 그전에는 비워 둔다.
RISKY_TLDS: frozenset[str] = frozenset()

# 공식 출처로 확인한 URL 단축 서비스의 등록 도메인 (확인일 2026-10-31).
# bit.ly      : Bitly 공식 사이트(bitly.com)가 단축 링크 예시로 bit.ly를 제시
# tinyurl.com : TinyURL 공식 서비스 사이트
# t.co        : X 공식 도움말 "About X's link service (http://t.co)"
# goo.gl은 Google이 서비스를 종료(2025-08)해서 넣지 않았다. is.gd는 공식 확인 전이라 보류.
SHORTENER_DOMAINS: frozenset[str] = frozenset({"bit.ly", "tinyurl.com", "t.co"})

# UTS #39 "highly restrictive" 기준에서 한 이름에 함께 써도 되는 문자 체계 조합
_ALLOWED_SCRIPT_SETS = (
    {"LATIN", "HAN", "HIRAGANA", "KATAKANA"},  # 일본어
    {"LATIN", "HAN", "BOPOMOFO"},  # 중국어
    {"LATIN", "HAN", "HANGUL"},  # 한국어
)


@dataclass(frozen=True)
class ParsedUrl:
    url: str
    scheme: str
    host: str  # 소문자, 퓨니코드
    unicode_host: str  # 사람이 읽는 형태. 동형문자 검사에 쓴다.
    registered_domain: str | None
    subdomain: str
    suffix: str
    port: int | None  # 기본 포트는 정규화 때 제거되어 None
    is_ip: bool
    has_userinfo: bool


def parse(raw: str) -> ParsedUrl:
    url = normalize(raw)
    parts = urlsplit(url)
    host = parts.hostname or ""
    is_ip = _is_ip_host(host)

    if is_ip:
        registered, subdomain, suffix = None, "", ""
    else:
        ext = _EXTRACTOR(host)
        registered = ext.top_domain_under_public_suffix or None
        subdomain, suffix = ext.subdomain, ext.suffix
        labels = host.split(".")
        if not suffix and len(labels) >= 2:
            # 목록에 없는 TLD(.test 등)는 PSL 표준 규칙대로 마지막 라벨을 TLD로 본다.
            suffix = labels[-1]
            registered = ".".join(labels[-2:])
            subdomain = ".".join(labels[:-2])

    return ParsedUrl(
        url=url,
        scheme=parts.scheme,
        host=host,
        unicode_host=_to_unicode_host(host),
        registered_domain=registered,
        subdomain=subdomain,
        suffix=suffix,
        port=parts.port,
        is_ip=is_ip,
        has_userinfo="@" in parts.netloc,
    )


def structure_signals(parsed: ParsedUrl) -> list[Signal]:
    signals: list[Signal] = []

    def add(kind: str, severity: str, summary: str) -> None:
        signals.append(
            Signal(id=f"sig-{kind}", kind=kind, severity=severity,
                   summary=summary, source=_SOURCE, evidenceIds=[])
        )

    if parsed.is_ip:
        add("ip_host", "medium", "도메인 이름 대신 IP 주소로 연결합니다.")
    if parsed.has_userinfo:
        add("userinfo_in_url", "medium", "주소에 '@'가 있어 실제 목적지가 다를 수 있습니다.")
    if parsed.subdomain and len(parsed.subdomain.split(".")) >= _DEEP_SUBDOMAIN_LABELS:
        add("deep_subdomain", "low", "서브도메인이 비정상적으로 깁니다.")
    if parsed.port is not None:
        add("nonstandard_port", "low", "일반적이지 않은 포트를 사용합니다.")
    if any(label.startswith("xn--") for label in parsed.host.split(".")):
        add("punycode_host", "low", "유니코드 도메인(퓨니코드)을 사용합니다.")
    if _has_mixed_script(parsed.unicode_host):
        add("mixed_script_host", "medium", "비슷하게 생긴 서로 다른 문자 체계가 한 이름에 섞여 있습니다.")
    if parsed.scheme == "http":
        add("plain_http", "info", "연결에 HTTPS 암호화가 적용되지 않았습니다.")
    if parsed.suffix and parsed.suffix.rsplit(".", 1)[-1] in RISKY_TLDS:
        add("risky_tld", "low", "악용 사례가 많은 최상위 도메인입니다.")
    if parsed.registered_domain in SHORTENER_DOMAINS:
        add("url_shortener", "low", "실제 주소를 숨기는 단축 주소 서비스입니다.")
    if len(parsed.url) >= _LONG_URL_LENGTH:
        add("long_url", "low", "주소가 지나치게 깁니다.")
    return signals


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # 브라우저가 IP로 해석하는 정수형(2130706433), 16진수형(0x7f000001) 표기
    return host.isdigit() or bool(_HEX_IP.fullmatch(host))


def _script_of(ch: str) -> str:
    name = unicodedata.name(ch, "")
    first = name.split(" ", 1)[0]
    return "HAN" if first == "CJK" else first


def _has_mixed_script(unicode_host: str) -> bool:
    """도메인의 각 라벨 안에서 문자 체계가 허용되지 않는 조합으로 섞였는지 본다."""
    for label in unicode_host.split("."):
        scripts = {_script_of(ch) for ch in label if ch.isalpha()}
        if len(scripts) > 1 and not any(scripts <= allowed for allowed in _ALLOWED_SCRIPT_SETS):
            return True
    return False


def _to_unicode_host(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna")
    except UnicodeError:
        return host
