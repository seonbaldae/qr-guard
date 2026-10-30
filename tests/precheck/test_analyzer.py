"""analyze() 테스트. 문서용 가짜 도메인만 쓴다."""

import pytest

from app.precheck.analyzer import analyze
from app.precheck.payload import InvalidPayload


def test_clean_url_static_clean():
    result = analyze("https://preview-demo.example.test/login")
    assert result.status == "completed"
    assert result.registeredDomain == "example.test"
    assert result.signals == []
    assert result.providers == []


def test_clean_result_never_claims_safe():
    # 신호가 없어도 검사하지 않은 범위를 반드시 적는다.
    result = analyze("https://example.com/")
    assert result.limitations
    assert any("목록" in item for item in result.limitations)


def test_suspicious_url_has_signals():
    result = analyze("http://192.0.2.1:8080/login")
    assert {s.kind for s in result.signals} == {"ip_host", "nonstandard_port", "plain_http"}
    assert result.registeredDomain is None


def test_evidence_ids_resolve_inside_same_result():
    result = analyze("https://user@a.b.c.example.com:8443/")
    known = {e.id for e in result.evidence}
    assert all(set(s.evidenceIds) <= known for s in result.signals)


def test_output_does_not_leak_query_or_credentials():
    result = analyze("https://user:secret@example.com/path?token=abc123#frag")
    dumped = result.model_dump_json()
    assert "secret" not in dumped
    assert "abc123" not in dumped
    assert "token" not in dumped


def test_limitations_list_is_not_shared_between_calls():
    first = analyze("https://example.com/")
    first.limitations.append("변경")
    assert "변경" not in analyze("https://example.com/").limitations


@pytest.mark.parametrize("raw", ["", "example.com", "ftp://example.com", "javascript:alert(1)"])
def test_invalid_input_raises(raw):
    with pytest.raises(InvalidPayload):
        analyze(raw)


def test_json_shape_matches_contract_keys():
    data = analyze("https://example.com/").model_dump()
    assert set(data) == {
        "status", "registeredDomain", "signals", "evidence", "providers", "limitations",
    }
