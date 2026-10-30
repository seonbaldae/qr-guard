"""Google v5 urls:search answers in Protobuf. Real captured bodies plus synthetic edge cases; no network."""

import httpx
import pytest

from app.precheck import safebrowsing as sb

# tests/conftest.py replaces sb._send with a guard for every test. Keep the real one: these tests run it
# against a fake transport, so the response parsing is exercised without any network access.
REAL_SEND = sb._send

# Bodies captured from the real API for Google's official test pages and a clean URL.
PHISHING = b"\n1\n,testsafebrowsing.appspot.com/s/phishing.html\x12\x01\x02\x12\x03\x08\xac\x02"
MALWARE = b"\n1\n+testsafebrowsing.appspot.com/s/malware.html\x12\x02\x01\x04\x12\x03\x08\xac\x02"
CLEAN = b"\x12\x03\x08\xac\x02"


def varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def field(number, payload):
    return varint(number << 3 | 2) + varint(len(payload)) + payload


@pytest.fixture(autouse=True)
def _clear_cache():
    sb._CACHE.clear()
    yield
    sb._CACHE.clear()


class FakeTransport:
    """Stands in for httpx.HTTPTransport so _send runs without touching the network."""

    response = httpx.Response(200)

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def handle_request(self, request):
        return type(self).response


def serve(monkeypatch, status=200, content_type="application/x-protobuf", body=b""):
    FakeTransport.response = httpx.Response(status, headers={"content-type": content_type}, content=body)
    monkeypatch.setattr(sb.httpx, "HTTPTransport", FakeTransport)
    monkeypatch.setattr(sb, "_send", REAL_SEND)


# --- decoder -----------------------------------------------------------------


def test_decodes_real_phishing_response():
    assert sb._decode_search_response(PHISHING) == {
        "threats": [{"url": "testsafebrowsing.appspot.com/s/phishing.html", "threatTypes": ["SOCIAL_ENGINEERING"]}],
        "cacheDuration": "300s",
    }


def test_decodes_real_malware_response_with_two_types():
    threat = sb._decode_search_response(MALWARE)["threats"][0]
    assert threat["threatTypes"] == ["MALWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


def test_decodes_clean_response_as_no_threats():
    assert sb._decode_search_response(CLEAN) == {"threats": [], "cacheDuration": "300s"}


def test_empty_body_is_no_threats():
    assert sb._decode_search_response(b"") == {"threats": []}


def test_unpacked_enum_values_and_unknown_values():
    threat = field(1, b"example.test/a") + varint(2 << 3) + varint(1) + varint(2 << 3) + varint(99)
    result = sb._decode_search_response(field(1, threat))
    assert result["threats"][0]["threatTypes"] == ["MALWARE", "THREAT_TYPE_UNSPECIFIED"]


def test_multiple_threats_and_nanos_duration():
    body = field(1, field(1, b"a.example.test") + field(2, b"\x01")) + field(1, field(1, b"b.example.test") + field(2, b"\x03"))
    body += field(2, varint(1 << 3) + varint(5) + varint(2 << 3) + varint(500_000_000))
    result = sb._decode_search_response(body)
    assert [t["threatTypes"] for t in result["threats"]] == [["MALWARE"], ["UNWANTED_SOFTWARE"]]
    assert result["cacheDuration"] == "5.5s"


def test_unknown_fields_are_skipped():
    body = varint(9 << 3) + varint(7) + field(7, b"ignored") + PHISHING
    assert sb._decode_search_response(body)["threats"][0]["threatTypes"] == ["SOCIAL_ENGINEERING"]


@pytest.mark.parametrize(
    "body",
    [
        b"\x0a",  # tag with no length
        b"\x0a\x05abc",  # length longer than data
        b"\x80",  # unterminated varint
        b"\xff" * 11 + b"\x01",  # varint too long
        b"\x00\x01",  # field number 0
        b"\x0b",  # unsupported wire type (start group)
        field(1, b"\x0a\x03\xff\xfe\xfd"),  # url is not UTF-8
        field(2, varint(2 << 3) + varint(1_000_000_000)),  # nanos out of range
        b"\x09\x00",  # truncated fixed64
    ],
)
def test_malformed_bodies_are_rejected(body):
    with pytest.raises(ValueError):
        sb._decode_search_response(body)


# --- _send and the full lookup ----------------------------------------------


def test_send_decodes_protobuf_only_when_status_ok(monkeypatch):
    serve(monkeypatch, body=PHISHING)
    status, payload = sb._send("https://testsafebrowsing.appspot.com/s/phishing.html", "k")
    assert status == 200 and payload["threats"][0]["threatTypes"] == ["SOCIAL_ENGINEERING"]


def test_send_keeps_json_error_bodies(monkeypatch):
    serve(monkeypatch, status=400, content_type="application/json; charset=UTF-8", body=b'{"error": {"code": 400}}')
    assert sb._send("https://example.com/", "k") == (400, {"error": {"code": 400}})


def test_send_returns_none_for_malformed_protobuf(monkeypatch):
    serve(monkeypatch, body=b"\x0a\x05abc")
    assert sb._send("https://example.com/", "k") == (200, None)


def test_known_threat_is_a_match(monkeypatch):
    serve(monkeypatch, body=PHISHING)
    result = sb.check_safe_browsing("https://testsafebrowsing.appspot.com/s/phishing.html", api_key="k1")
    assert (result.provider.status, result.provider.matched) == ("checked", True)
    assert result.signals[0].kind == "known_threat_match" and result.signals[0].severity == "high"
    assert result.evidence[0].data == {"threatTypes": "SOCIAL_ENGINEERING"}


def test_malware_threat_lists_both_types(monkeypatch):
    serve(monkeypatch, body=MALWARE)
    result = sb.check_safe_browsing("https://testsafebrowsing.appspot.com/s/malware.html", api_key="k2")
    assert result.evidence[0].data == {"threatTypes": "MALWARE,POTENTIALLY_HARMFUL_APPLICATION"}


def test_clean_response_is_checked_not_matched(monkeypatch):
    serve(monkeypatch, body=CLEAN)
    result = sb.check_safe_browsing("https://example.com/", api_key="k3")
    assert (result.provider.status, result.provider.matched) == ("checked", False)
    assert result.signals == [] and result.evidence == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status": 403, "content_type": "application/json", "body": b'{"error": {}}'},
        {"status": 429, "content_type": "application/json", "body": b'{"error": {}}'},
        {"status": 200, "content_type": "application/x-protobuf", "body": b"\x0a\x05abc"},
        {"status": 200, "content_type": "text/html", "body": b"<html></html>"},
    ],
)
def test_errors_and_garbage_stay_unknown_not_clean(monkeypatch, kwargs):
    serve(monkeypatch, **kwargs)
    result = sb.check_safe_browsing("https://example.com/", api_key="k4")
    assert (result.provider.status, result.provider.matched) == ("failed", None)
