"""Known Protobuf fields with invalid wire types must fail closed."""
import httpx
import pytest

from app.precheck import safebrowsing as sb

REAL_SEND = sb._send


@pytest.mark.parametrize('body', [
    b'\x08\x01',  # threats must be length-delimited, not a varint
    b'\x09' + b'\x00' * 8,  # threats must not be fixed64
    b'\x0d' + b'\x00' * 4,  # threats must not be fixed32
    b'\x10\x01',  # cache_duration must be length-delimited
    b'\x0a\x02\x08\x01',  # ThreatUrl.url must be length-delimited
    b'\x0a\x05\x15' + b'\x00' * 4,  # threat_types must be packed or varint
    b'\x12\x02\x0a\x00',  # Duration.seconds must be a varint
    b'\x12\x02\x12\x00',  # Duration.nanos must be a varint
])
def test_known_fields_with_wrong_wire_types_are_rejected(body):
    with pytest.raises(ValueError):
        sb._decode_search_response(body)


def test_wrong_wire_threat_field_fails_lookup_instead_of_reporting_clean(monkeypatch):
    transport = httpx.MockTransport(lambda request: httpx.Response(
        200, headers={'content-type': 'application/x-protobuf'}, content=b'\x08\x01'))
    monkeypatch.setattr(sb.httpx, 'HTTPTransport', lambda **kwargs: transport)
    monkeypatch.setattr(sb, '_send', REAL_SEND)
    sb._CACHE.clear()
    try:
        result = sb.check_safe_browsing('https://example.com/', api_key='test-wire-type')
        assert result.provider.status == 'failed'
        assert result.provider.matched is None
        assert not result.signals and not result.evidence
    finally:
        sb._CACHE.clear()
