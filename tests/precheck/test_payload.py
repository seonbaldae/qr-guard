"""normalize() 테스트. 문서용 가짜 도메인(example.*)만 쓰고 실제 접속은 하지 않는다."""

import pytest

from app.precheck.payload import InvalidPayload, normalize

# (입력, 정규화 결과) — 정상 입력 22개
VALID = [
    ("https://example.com", "https://example.com/"),
    ("  https://example.com/login  ", "https://example.com/login"),
    ("https://example.com/\n", "https://example.com/"),
    ("HTTPS://EXAMPLE.COM/Path", "https://example.com/Path"),
    ("http://example.com:80/", "http://example.com/"),
    ("https://example.com:443/a", "https://example.com/a"),
    ("https://example.com./", "https://example.com/"),
    ("https://example.com:8443/", "https://example.com:8443/"),
    ("http://example.com:443/", "http://example.com:443/"),
    ("https://www.example.com/a?b=1&c=2", "https://www.example.com/a?b=1&c=2"),
    ("https://example.com/#frag", "https://example.com/#frag"),
    ("https://sub.example.co.uk/x", "https://sub.example.co.uk/x"),
    ("https://example.test/로그인", "https://example.test/로그인"),
    ("https://한글.example.test/", "https://xn--bj0bj06e.example.test/"),
    ("https://пример.test/", "https://xn--e1afmkfd.test/"),
    ("https://EXAMPLE.test:443", "https://example.test/"),
    ("http://192.0.2.1/login", "http://192.0.2.1/login"),
    ("https://[2001:db8::1]/", "https://[2001:db8::1]/"),
    ("https://user@example.com/", "https://user@example.com/"),
    ("https://example.com?x=1", "https://example.com/?x=1"),
    ("http://localhost/", "http://localhost/"),
    ("https://a.b.c.example.org/%E2%9C%93", "https://a.b.c.example.org/%E2%9C%93"),
]

# 거부해야 하는 입력 26개
INVALID = [
    "",
    "   ",
    None,
    123,
    "example.com/login",
    "//example.com",
    "ftp://example.com",
    "javascript:alert(1)",
    "data:text/html,hi",
    "file:///etc/passwd",
    "mailto:a@example.com",
    "tel:+82123456789",
    "https://",
    "https:///path",
    "https://exa mple.com",
    "https://example.com/a\nb",
    "https://example.com/a\tb",
    "https://example.com/\x00",
    "https://example.com/‮",
    "https://example.com\\@example.test/",
    "https://example.com:99999/",
    "https://example.com:abc/",
    "https://a..b.example.com/",
    "https://" + "a" * 64 + ".com/",
    "http://[::1",
    "https://example.com/" + "a" * 2050,
]


@pytest.mark.parametrize("raw, expected", VALID)
def test_normalize_valid(raw, expected):
    assert normalize(raw) == expected


@pytest.mark.parametrize("raw", INVALID)
def test_normalize_invalid(raw):
    with pytest.raises(InvalidPayload):
        normalize(raw)


@pytest.mark.parametrize("raw, _", VALID)
def test_normalize_is_idempotent(raw, _):
    once = normalize(raw)
    assert normalize(once) == once


def test_counts_meet_minimum():
    assert len(VALID) >= 20
    assert len(INVALID) >= 20
