"""Safe Browsing 연동 테스트. 가짜 전송 함수만 쓰고 실제 Google API는 호출하지 않는다."""

import pytest
import requests

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


MATCH = {"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "x"}}]}

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
    assert result.provider.name == "google-safebrowsing"
    assert (result.provider.status, result.provider.matched) == ("checked", False)
    assert result.provider.checkedAt is not None
    assert result.signals == [] and result.evidence == []


@pytest.mark.parametrize("url", BAD)
def test_match_response_creates_signal_and_evidence(url):
    result = run(url, FakeSend(payload=MATCH))
    assert (result.provider.status, result.provider.matched) == ("checked", True)
    assert [s.kind for s in result.signals] == ["threat_feed_match"]
    assert result.signals[0].severity == "high"
    assert result.signals[0].evidenceIds == [result.evidence[0].id]
    assert result.evidence[0].data == {"threatTypes": "SOCIAL_ENGINEERING"}


def test_counts_meet_minimum():
    assert len(CLEAN) >= 20 and len(BAD) >= 20


def test_request_body_shape():
    send = FakeSend()
    run("https://example.com/a", send)
    body, key = send.calls[0]
    info = body["threatInfo"]
    assert key == KEY
    assert info["threatTypes"] == ["SOCIAL_ENGINEERING", "MALWARE"]
    assert info["threatEntryTypes"] == ["URL"]
    assert info["platformTypes"] == ["ANY_PLATFORM"]
    assert body["client"]["clientId"]


@pytest.mark.parametrize(
    "raw, sent",
    [
        ("https://example.com/a?token=abc123&user=kim", "https://example.com/a"),
        ("https://example.com/a#secret-frag", "https://example.com/a"),
        ("https://user:pw@example.com/a", "https://example.com/a"),
        ("https://user@example.com:8443/a?x=1#y", "https://example.com:8443/a"),
        ("HTTPS://EXAMPLE.COM:443", "https://example.com/"),
        ("https://한글.example.test/p?q=1", "https://xn--bj0bj06e.example.test/p"),
    ],
)
def test_only_scheme_host_path_are_sent(raw, sent):
    send = FakeSend()
    run(raw, send)
    assert send.calls[0][0]["threatInfo"]["threatEntries"] == [{"url": sent}]


def test_missing_key_is_unknown_and_makes_no_call():
    send = FakeSend()
    for key in (None, "", "   "):
        result = check_safe_browsing("https://example.com/", api_key=key, send=send)
        assert (result.provider.status, result.provider.matched) == ("failed", None)
        assert result.provider.checkedAt is None
    assert send.calls == []


@pytest.mark.parametrize(
    "line",
    [f"SAFE_BROWSING_API_KEY={KEY}", f'SAFE_BROWSING_API_KEY="{KEY}"', f"  SAFE_BROWSING_API_KEY = '{KEY}'  "],
)
def test_key_is_read_from_env_file(monkeypatch, tmp_path, line):
    env_file = tmp_path / ".env"
    env_file.write_text(f"# note\nOTHER=1\n{line}\n", encoding="utf-8")
    monkeypatch.setattr("app.precheck.safebrowsing.ENV_FILE", env_file)
    send = FakeSend()
    assert check_safe_browsing("https://example.com/", send=send).provider.status == "checked"
    assert send.calls[0][1] == KEY


def test_environment_variable_wins_over_env_file(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("SAFE_BROWSING_API_KEY=FROM-FILE\n", encoding="utf-8")
    monkeypatch.setattr("app.precheck.safebrowsing.ENV_FILE", env_file)
    monkeypatch.setenv(API_KEY_ENV, "FROM-ENV")
    send = FakeSend()
    check_safe_browsing("https://example.com/", send=send)
    assert send.calls[0][1] == "FROM-ENV"


def test_env_file_without_the_key_is_unknown(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("OTHER=1\n", encoding="utf-8")
    monkeypatch.setattr("app.precheck.safebrowsing.ENV_FILE", env_file)
    send = FakeSend()
    assert check_safe_browsing("https://example.com/", send=send).provider.status == "failed"
    assert send.calls == []


def test_key_is_read_from_environment(monkeypatch):
    monkeypatch.setenv(API_KEY_ENV, KEY)
    send = FakeSend()
    result = check_safe_browsing("https://example.com/", send=send)
    assert result.provider.status == "checked"
    assert send.calls[0][1] == KEY


@pytest.mark.parametrize("status", [400, 401, 403, 429, 500, 503])
def test_http_errors_are_unknown_not_clean(status):
    result = run("https://example.com/", FakeSend(status=status, payload={"error": {}}))
    assert (result.provider.status, result.provider.matched) == ("failed", None)


@pytest.mark.parametrize("error", [requests.Timeout("t"), requests.ConnectionError("c")])
def test_network_errors_are_unknown_and_do_not_leak_key(error):
    send = FakeSend(error=requests.ConnectionError(f"failed ...?key={KEY}"))
    result = run("https://example.com/", send)
    assert (result.provider.status, result.provider.matched) == ("failed", None)
    assert KEY not in result.provider.model_dump_json()
    assert run("https://example.com/", FakeSend(error=error)).provider.status == "failed"


@pytest.mark.parametrize(
    "payload", [None, [], "text", {"matches": "x"}, {"matches": [1]}, {"matches": None}]
)
def test_unexpected_payload_is_unknown(payload):
    result = run("https://example.com/", FakeSend(payload=payload))
    assert result.provider.status == "failed"


def test_empty_matches_list_is_not_a_match():
    result = run("https://example.com/", FakeSend(payload={"matches": []}))
    assert (result.provider.status, result.provider.matched) == ("checked", False)


def test_multiple_threat_types_are_sorted_and_deduplicated():
    payload = {"matches": [{"threatType": "MALWARE"}, {"threatType": "SOCIAL_ENGINEERING"}, {"threatType": "MALWARE"}]}
    result = run("https://example.com/", FakeSend(payload=payload))
    assert result.evidence[0].data == {"threatTypes": "MALWARE,SOCIAL_ENGINEERING"}


def test_odd_threat_type_values_are_ignored_but_still_a_match():
    payload = {"matches": [{"threatType": "evil <script>"}, {"threatType": 5}, {}]}
    result = run("https://example.com/", FakeSend(payload=payload))
    assert result.provider.matched is True
    assert result.evidence[0].data is None


def test_output_does_not_contain_url_query_or_key():
    send = FakeSend(payload=MATCH)
    result = run("https://user:pw@example.com/a?token=abc123#frag", send)
    dumped = "".join(m.model_dump_json() for m in [result.provider, *result.signals, *result.evidence])
    for secret in ("abc123", "token", "pw", "frag", KEY, "example.com"):
        assert secret not in dumped


def test_invalid_url_is_unknown_and_makes_no_call():
    send = FakeSend()
    result = run("javascript:alert(1)", send)
    assert result.provider.status == "failed"
    assert send.calls == []
