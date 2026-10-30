"""analyze() 테스트. 문서용 가짜 도메인과 가짜 Safe Browsing 응답만 쓴다."""

import pytest

from app.precheck.analyzer import analyze
from app.precheck.payload import InvalidPayload
from app.precheck.safebrowsing import check_safe_browsing

MATCH = {"threats": [{"threatTypes": ["SOCIAL_ENGINEERING"]}]}


def fake_check(status=200, payload=None):
    """실제 호출 없이 응답을 흉내 내는 조회 함수."""
    return lambda url: check_safe_browsing(
        url, api_key="k", send=lambda body, key: (status, {} if payload is None else payload)
    )


def test_static_clean():
    """계약 Fixture '정적 정상': 조회 성공, 미일치, 한계 없음."""
    result = analyze("https://preview-demo.example.test/login", fake_check())
    assert result.status == "completed"
    assert result.registeredDomain == "example.test"
    assert result.signals == []
    assert result.limitations == []
    provider = result.providers[0]
    assert (provider.name, provider.status, provider.matched) == ("google_safe_browsing", "checked", False)
    assert provider.checkedAt is not None


def test_known_malicious():
    """계약 Fixture '알려진 악성': 일치, 신호와 증거 연결."""
    result = analyze("https://phishing-demo.example.test", fake_check(payload=MATCH))
    assert result.providers[0].matched is True
    assert result.signals[0].kind == "known_threat_match"
    assert result.signals[0].severity == "high"
    assert [e.kind for e in result.evidence] == ["known_threat_match"]
    assert result.signals[0].evidenceIds == [result.evidence[0].id]


def test_lookup_failed():
    """계약 Fixture '조회 실패': 깨끗함이 아니라 확인 못 함."""
    result = analyze("https://unknown-demo.example.test", fake_check(status=503))
    provider = result.providers[0]
    assert (provider.status, provider.matched, provider.checkedAt) == ("failed", None, None)
    assert result.signals == []
    assert result.limitations == ["Google Safe Browsing 조회를 완료하지 못했습니다."]


def test_default_without_api_key_is_unknown_and_never_calls_network():
    # conftest가 키를 지워 두므로 기본 조회 함수는 호출 없이 failed가 된다.
    result = analyze("https://example.com/")
    assert result.providers[0].status == "failed"
    assert result.providers[0].matched is None


def test_structure_signals_still_reported():
    result = analyze("http://192.0.2.1:8080/login", fake_check())
    assert {s.kind for s in result.signals} == {"ip_host", "nonstandard_port", "plain_http"}
    assert result.registeredDomain is None


def test_threat_signal_comes_first_with_structure_signals():
    result = analyze("http://192.0.2.1:8080/login", fake_check(payload=MATCH))
    kinds = [s.kind for s in result.signals]
    assert kinds[0] == "known_threat_match"
    assert {"ip_host", "nonstandard_port", "plain_http"} <= set(kinds)


def test_evidence_ids_resolve_inside_same_result():
    result = analyze("https://phishing-demo.example.test/", fake_check(payload=MATCH))
    known = {e.id for e in result.evidence}
    assert all(set(s.evidenceIds) <= known for s in result.signals)


def test_output_does_not_leak_query_or_credentials():
    result = analyze("https://user:secret@example.com/path?token=abc123#frag", fake_check(payload=MATCH))
    dumped = result.model_dump_json()
    assert "secret" not in dumped and "abc123" not in dumped and "token" not in dumped


def test_lookup_receives_normalized_url():
    seen = []
    analyze("HTTPS://EXAMPLE.COM:443", lambda url: seen.append(url) or fake_check()(url))
    assert seen == ["https://example.com/"]


def test_limitations_list_is_not_shared_between_calls():
    first = analyze("https://example.com/", fake_check(status=500))
    first.limitations.append("변경")
    assert "변경" not in analyze("https://example.com/", fake_check(status=500)).limitations


@pytest.mark.parametrize("raw", ["", "example.com", "ftp://example.com", "javascript:alert(1)"])
def test_invalid_input_raises_before_any_lookup(raw):
    calls = []
    with pytest.raises(InvalidPayload):
        analyze(raw, lambda url: calls.append(url))
    assert calls == []


def test_json_shape_matches_contract_keys():
    data = analyze("https://example.com/", fake_check()).model_dump()
    assert set(data) == {
        "status", "registeredDomain", "signals", "evidence", "providers", "limitations",
    }
