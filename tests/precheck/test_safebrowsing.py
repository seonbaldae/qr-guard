"""Safe Browsing 연동 테스트. 가짜 전송 함수만 쓰고 실제 Google API는 호출하지 않는다."""

import pytest

import httpx
import logging
from app.precheck.safebrowsing import _send as real_send

from app.precheck.safebrowsing import API_KEY_ENV, check_safe_browsing

KEY = "TEST-SECRET-KEY-123"


_EMPTY = object()


class FakeSend:
    def __init__(self, status=200, payload=_EMPTY, error=None):
        # payload=None은 "응답이 JSON이 아님"을, 생략은 일치 없음({})을 뜻한다.
        self.status, self.payload, self.error = status, {} if payload is _EMPTY else payload, error
        self.calls = []

    def __call__(self, body, api_key):
        self.calls.append((body, api_key))
        if self.error:
            raise self.error
        return self.status, self.payload


def run(url, send, key=KEY):
    return check_safe_browsing(url, api_key=key, send=send)


MATCH = {"threats": [{"threatTypes": ["SOCIAL_ENGINEERING"], "url": "x"}]}

# 일치 없음(빈 객체)이어야 하는 정상 URL 22개
CLEAN = [
    "https://example.com/", "https://www.example.com/", "https://example.org/a",
    "https://example.net/x?y=1", "https://shop.example.com/", "https://sub.example.co.uk/",
    "https://example.test/login", "https://preview-demo.example.test/login",
    "https://a.b.example.com/", "https://example.com:443/", "https://EXAMPLE.COM/Path",
    "https://example.com/a/b/c?d=e#f", "https://pay.example.test/checkout",
    "https://m.example.org/", "https://docs.example.net/guide", "https://example.co.kr/",
    "https://www.example.co.kr/menu", "https://example.com/로그인",
    "https://example.test/?a=1&b=2", "https://static.example.test/img.png",
    "http://example.com/", "https://한글.example.test/",
]

# 일치로 응답받는 수상한 URL 22개
BAD = [
    "https://phishing-demo.example.test/", "http://phishing-demo.example.test/login",
    "https://login.secure.account.example.test/", "https://a.b.c.example.com/",
    "http://192.0.2.1/", "https://192.0.2.1:8443/login", "https://[2001:db8::1]/",
    "https://user@example.com/", "https://example.com@example.test/",
    "https://xn--bj0bj06e.example.test/", "https://exаmple.test/",
    "https://bit.ly/abc123", "https://t.co/abc123", "https://tinyurl.com/abc123",
    "https://example.com/" + "a" * 300, "https://example.com:8080/",
    "http://a.b.c.d.example.test:8080/", "https://2130706433/",
    "https://0x7f000001/", "https://evil.example.test/login?next=/home",
    "https://evil.example.test/a#frag", "http://xn--e1afmkfd.example.test/",
]


@pytest.mark.parametrize("url", CLEAN)
def test_clean_response_is_checked_not_matched(url):
    result = run(url, FakeSend(payload={}))
    assert result.provider.name == "google_safe_browsing"
    assert (result.provider.status, result.provider.matched) == ("checked", False)
    assert result.provider.checkedAt is not None
    assert result.signals == [] and result.evidence == []


@pytest.mark.parametrize("url", BAD)
def test_match_response_creates_signal_and_evidence(url):
    result = run(url, FakeSend(payload=MATCH))
    assert (result.provider.status, result.provider.matched) == ("checked", True)
    assert [s.kind for s in result.signals] == ["known_threat_match"]
    assert result.signals[0].severity == "high"
    assert result.signals[0].evidenceIds == [result.evidence[0].id]
    assert result.evidence[0].data == {"threatTypes": "SOCIAL_ENGINEERING"}


def test_counts_meet_minimum():
    assert len(CLEAN) >= 20 and len(BAD) >= 20


def test_v5_passes_normalized_url_with_query():
    send = FakeSend()
    result = run("https://EXAMPLE.com/a?token=abc", send)
    assert send.calls == [("https://example.com/a?token=abc", KEY)]
    assert result.provider.name == "google_safe_browsing"


def test_v5_positive_does_not_echo_expression():
    result = run("https://example.com/a", FakeSend(payload={"threats": [{"url": "secret-expression", "threatTypes": ["MALWARE"]}]}))
    assert result.provider.matched is True
    assert result.evidence[0].kind == result.signals[0].kind == "known_threat_match"
    assert "secret-expression" not in result.evidence[0].model_dump_json()


def test_cache_positive_and_negative_until_expiry(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("app.precheck.safebrowsing.time.monotonic", lambda: clock[0])
    for matched in (False, True):
        calls = []
        payload = {"cacheDuration": "0.125s", "threats": [{"threatTypes": ["MALWARE"]}] if matched else []}
        send = lambda u, k: (calls.append(u) or (200, payload))
        url = f"https://cache-{matched}.example/"
        assert run(url, send).provider.matched is matched
        clock[0] += 0.1
        assert run(url, send).provider.matched is matched
        assert len(calls) == 1
        clock[0] += 0.025
        run(url, send)
        assert len(calls) == 2


@pytest.mark.parametrize("payload", [{"threats": None}, {"threats": [3]}, {"threats": [{"threatTypes": None}]}, {"cacheDuration": "-1s"}, {"cacheDuration": "0.1234567890s"}])
def test_malformed_responses_fail(payload):
    assert run("https://malformed.example/", FakeSend(payload=payload)).provider.matched is None


def test_explicit_empty_canonical_env_disables_legacy(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "legacy")
    send = FakeSend()
    assert check_safe_browsing("https://env.example/", send=send).provider.status == "failed"
    assert not send.calls


def test_transport_uses_v5_and_never_logs_query_or_key(monkeypatch, caplog):
    seen = []
    def handle(request):
        seen.append(request)
        return httpx.Response(200, json={})
    monkeypatch.setattr("app.precheck.safebrowsing.httpx.HTTPTransport", lambda **kw: httpx.MockTransport(handle))
    monkeypatch.setattr("app.precheck.safebrowsing._send", real_send)
    caplog.set_level(logging.INFO)
    result = check_safe_browsing("https://wire.example/?token=private", api_key=KEY)
    assert result.provider.matched is False
    req = seen[0]
    assert req.method == "GET" and req.url.path == "/v5/urls:search"
    assert req.url.params.get_list("urls") == ["https://wire.example/?token=private"]
    assert req.headers["X-Goog-Api-Key"] == KEY and not req.content
    assert "private" not in caplog.text and KEY not in caplog.text


def test_cache_isolated_by_url_and_key_and_failures_not_cached():
    calls = []
    def send(url, key):
        calls.append((url, key))
        return (503, {}) if key == "bad" else (200, {"cacheDuration": "60s"})
    for key, url in [("one", "https://x.example/?a=1"), ("two", "https://x.example/?a=1"), ("one", "https://x.example/?a=2"), ("bad", "https://x.example/") , ("bad", "https://x.example/")]:
        check_safe_browsing(url, api_key=key, send=send)
    assert len(calls) == 5
    from app.precheck import safebrowsing as sb
    assert all(isinstance(k, bytes) and b"one" not in k for k in sb._CACHE)


def test_transport_response_limit_and_redirect_fail(monkeypatch):
    from app.precheck import safebrowsing as sb
    for response in (httpx.Response(200, content=b"x" * (1024 * 1024 + 1)), httpx.Response(302, headers={"location": "https://redirect.example/"})):
        monkeypatch.setattr(sb.httpx, "HTTPTransport", lambda **kw: httpx.MockTransport(lambda request: response))
        assert check_safe_browsing("https://large.example/", api_key=KEY, send=real_send).provider.status == "failed"


def test_untrusted_threat_type_does_not_echo_google_data():
    result = run("https://untrusted.example/", FakeSend(payload={"threats": [{"url": "secret", "threatTypes": ["PRIVATESECRET"]}]}))
    assert result.provider.matched is True
    assert "PRIVATESECRET" not in result.evidence[0].model_dump_json()
