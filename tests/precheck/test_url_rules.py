"""parse(), structure_signals() 테스트. 문서용 가짜 도메인만 쓴다."""

import pytest

from app.precheck.url_rules import parse, structure_signals

# 신호가 하나도 없어야 하는 정상 URL 22개
CLEAN = [
    "https://example.com/",
    "https://www.example.com/",
    "https://example.org/a",
    "https://example.net/x?y=1",
    "https://shop.example.com/",
    "https://sub.example.co.uk/",
    "https://example.test/login",
    "https://preview-demo.example.test/login",
    "https://a.b.example.com/",
    "https://example.com:443/",
    "https://example.com./",
    "https://EXAMPLE.COM/Path",
    "https://example.com/a/b/c?d=e#f",
    "https://pay.example.test/checkout",
    "https://m.example.org/",
    "https://docs.example.net/guide",
    "https://example.com/%E2%9C%93",
    "https://example.co.kr/",
    "https://www.example.co.kr/menu",
    "https://example.com/로그인",
    "https://example.test/?a=1&b=2",
    "https://static.example.test/img.png",
    "https://example.com/" + "a" * 179,  # 199자: 길이 경계 바로 아래
    "https://bit.ly.example.test/",  # 단축 서비스 이름이 서브도메인일 뿐
    "https://notbit.ly.example.test/",
]

# (입력, 기대하는 신호 kind 집합) — 수상한 URL 22개
SUSPICIOUS = [
    ("http://example.com/", {"plain_http"}),
    ("http://192.0.2.1/", {"ip_host", "plain_http"}),
    ("https://192.0.2.1/", {"ip_host"}),
    ("https://[2001:db8::1]/", {"ip_host"}),
    ("http://[::1]/", {"ip_host", "plain_http"}),
    ("https://2130706433/", {"ip_host"}),
    ("https://0x7f000001/", {"ip_host"}),
    ("https://user@example.com/", {"userinfo_in_url"}),
    ("https://example.com@example.test/", {"userinfo_in_url"}),
    ("https://user:pass@192.0.2.1:8443/", {"ip_host", "userinfo_in_url", "nonstandard_port"}),
    ("https://a.b.c.example.com/", {"deep_subdomain"}),
    ("https://w.x.y.z.example.com/", {"deep_subdomain"}),
    ("https://login.secure.account.example.test/", {"deep_subdomain"}),
    ("http://a.b.c.d.example.test:8080/", {"deep_subdomain", "nonstandard_port", "plain_http"}),
    ("https://example.com:8443/", {"nonstandard_port"}),
    ("https://example.com:8080/", {"nonstandard_port"}),
    ("http://example.com:443/", {"nonstandard_port", "plain_http"}),
    ("https://xn--bj0bj06e.example.test/", {"punycode_host"}),
    ("https://한글.example.test/", {"punycode_host"}),
    ("https://пример.test/", {"punycode_host"}),
    ("http://login.example.test/", {"plain_http"}),
    ("http://xn--e1afmkfd.example.test:8080/", {"punycode_host", "nonstandard_port", "plain_http"}),
    # 문자 체계 혼합: 라틴 e,x,m,p,l 사이에 키릴 а(U+0430) 또는 그리스 ο(U+03BF)
    ("https://exаmple.test/", {"punycode_host", "mixed_script_host"}),
    ("https://οpenexample.test/", {"punycode_host", "mixed_script_host"}),
    # 한국어, 일본어에서 흔한 조합은 혼합으로 보지 않는다
    ("https://삼성sds.example.test/", {"punycode_host"}),
    ("https://日本語abc.example.test/", {"punycode_host"}),
    # 단축 주소
    ("https://bit.ly/abc123", {"url_shortener"}),
    ("https://www.bit.ly/abc123", {"url_shortener"}),
    ("https://tinyurl.com/abc123", {"url_shortener"}),
    ("https://t.co/abc123", {"url_shortener"}),
    ("http://bit.ly/abc123", {"url_shortener", "plain_http"}),
    # 긴 주소 (정확히 200자)
    ("https://example.com/" + "a" * 180, {"long_url"}),
    ("https://example.com/" + "a" * 500, {"long_url"}),
]


@pytest.mark.parametrize("raw", CLEAN)
def test_clean_urls_have_no_signals(raw):
    assert structure_signals(parse(raw)) == []


@pytest.mark.parametrize("raw, kinds", SUSPICIOUS)
def test_suspicious_urls_signals(raw, kinds):
    assert {s.kind for s in structure_signals(parse(raw))} == kinds


def test_signals_do_not_reference_missing_evidence():
    for raw, _ in SUSPICIOUS:
        assert all(s.evidenceIds == [] for s in structure_signals(parse(raw)))


@pytest.mark.parametrize(
    "raw, registered, subdomain",
    [
        ("https://www.example.co.uk/", "example.co.uk", "www"),
        ("https://a.b.example.com/", "example.com", "a.b"),
        ("https://example.com/", "example.com", ""),
        ("https://192.0.2.1/", None, ""),
        ("https://[2001:db8::1]/", None, ""),
        ("https://localhost/", None, ""),
        ("https://한글.example.test/", "example.test", "xn--bj0bj06e"),
    ],
)
def test_registered_domain(raw, registered, subdomain):
    parsed = parse(raw)
    assert parsed.registered_domain == registered
    assert parsed.subdomain == subdomain


def test_unicode_host_is_kept_for_homoglyph_checks():
    assert parse("https://한글.example.test/").unicode_host == "한글.example.test"


def test_counts_meet_minimum():
    assert len(CLEAN) >= 20
    assert len(SUSPICIOUS) >= 20
