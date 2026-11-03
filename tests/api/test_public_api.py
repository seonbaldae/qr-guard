"""Stateless deployment boundaries. All threat lookups are explicit doubles."""

import asyncio
import time

import httpx
import pytest

from app.public_api import MAX_REQUEST_BYTES, create_public_app
from tests.api.support import fake_google, google_result


def client(application):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="https://qr.test")


def test_capabilities_are_explicit_and_health_contains_no_secrets():
    async def scenario():
        async with client(create_public_app(threat_check=fake_google())) as api:
            response = await api.get("/api/capabilities")
            assert response.json() == {
                "scanTransport": "direct", "scanMode": "static", "analysisScope": "static",
                "previewAvailable": False, "reportAvailable": False,
            }
            health = await api.get("/api/health")
            assert health.json() == {"status": "ok", **response.json()}
            for item in (response, health):
                assert item.headers["cache-control"] == "no-store"
                assert item.headers["x-content-type-options"] == "nosniff"
                assert "key" not in item.text.lower()
    asyncio.run(scenario())


def test_public_scan_finishes_in_one_request_and_never_claims_a_screenshot():
    async def scenario():
        async with client(create_public_app(threat_check=fake_google())) as api:
            response = await api.post("/api/analyze", json={
                "url": "https://example.test/path?review=public", "source": "manual", "mode": "sandbox",
            })
            assert response.status_code == 200
            result = response.json()
            assert result["status"] == "completed" and result["mode"] == "static"
            assert result["analysisScope"] == "static"
            assert result["verdict"]["level"] == "unknown"
            assert result["staticAnalysis"]["providers"][0]["status"] == "checked"
            assert result["staticAnalysis"]["providers"][0]["matched"] is False
            assert result["requestedUrl"] == "https://example.test/path?review=public"
            sandbox = result["sandboxAnalysis"]
            assert sandbox["status"] == "not_requested" and sandbox["skipReason"] == "static_only"
            assert sandbox["finalUrl"] is None
            assert sandbox["screenshot"]["available"] is False
            assert result["previewAvailable"] is False and result["reportAvailable"] is False
            assert result["reportCount"] is None and result["isReported"] is None
            assert result["reportedByUser"] is None
            assert "Docker" in " ".join(sandbox["limitations"])
            assert response.headers["cache-control"] == "no-store"
            # The returned identifier correlates this result; it is not a
            # serverless job or a claim that another instance can retrieve it.
            assert (await api.get(f'/api/scans/{result["scanId"]}')).status_code == 404
    asyncio.run(scenario())


def test_unlisted_mock_page_is_not_promoted_to_clear_and_keeps_observed_signals():
    async def scenario():
        target = "http://survey-training.example.test/login"
        async with client(create_public_app(threat_check=fake_google())) as api:
            result = (await api.post("/api/analyze", json={"url": target})).json()
            assert result["status"] == "completed"
            assert result["verdict"]["level"] == "unknown"
            assert result["verdict"]["reasons"] == [
                "알려진 위협 목록에서는 발견되지 않았지만 사이트 화면과 동작을 검사하지 않아 판단을 보류했습니다."
            ]
            provider = result["staticAnalysis"]["providers"][0]
            assert provider["status"] == "checked" and provider["matched"] is False
            assert any(item["kind"] == "plain_http" for item in result["staticAnalysis"]["signals"])
            assert result["sandboxAnalysis"]["status"] == "not_requested"
            assert result["sandboxAnalysis"]["finalUrl"] is None
    asyncio.run(scenario())


def test_malicious_static_result_preserves_provider_evidence():
    async def scenario():
        target = "https://example.test/known-threat"
        async with client(create_public_app(threat_check=fake_google([target]))) as api:
            result = (await api.post("/api/analyze", json={"url": target})).json()
            assert result["verdict"]["level"] == "malicious"
            assert result["staticAnalysis"]["providers"][0]["matched"] is True
            assert result["verdict"]["evidenceIds"] == ["ev-google"]
            assert result["evidence"][0]["id"] == "ev-google"
            assert result["sandboxAnalysis"]["finalUrl"] is None
    asyncio.run(scenario())


@pytest.mark.parametrize("lookup", [
    fake_google(status="failed"), fake_google(status="stale"),
    lambda _url: google_result(matched=None),
])
def test_failed_or_incomplete_provider_is_unknown(lookup):
    async def scenario():
        async with client(create_public_app(threat_check=lookup)) as api:
            result = (await api.post("/api/analyze", json={"url": "https://example.test/"})).json()
            assert result["status"] == "completed"
            assert result["verdict"]["level"] == "unknown"
            assert result["reportCount"] is None
    asyncio.run(scenario())


def test_transport_exception_is_not_echoed_and_does_not_become_clear():
    def failing(_url):
        raise OSError("SECRET_PROVIDER_TOKEN https://secret.example/?token=PRIVATE")

    async def scenario():
        async with client(create_public_app(threat_check=failing)) as api:
            response = await api.post("/api/analyze", json={"url": "https://example.test/"})
            result = response.json()
            assert result["verdict"]["level"] == "unknown"
            assert result["staticAnalysis"]["status"] == "failed"
            assert result["staticAnalysis"]["providers"][0]["matched"] is None
            assert "SECRET_PROVIDER_TOKEN" not in response.text and "PRIVATE" not in response.text
    asyncio.run(scenario())


def test_missing_key_is_a_provider_failure_without_real_transport(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

    async def scenario():
        async with client(create_public_app()) as api:
            result = (await api.post("/api/analyze", json={"url": "https://example.test/"})).json()
            assert result["verdict"]["level"] == "unknown"
            assert result["staticAnalysis"]["providers"][0]["status"] == "failed"
    asyncio.run(scenario())


def test_lookup_timeout_returns_unknown(monkeypatch):
    monkeypatch.setattr("app.public_api.LOOKUP_TIMEOUT_SECONDS", 0.001)

    def slow(_url):
        time.sleep(0.02)
        return google_result()

    async def scenario():
        async with client(create_public_app(threat_check=slow)) as api:
            result = (await api.post("/api/analyze", json={"url": "https://example.test/"})).json()
            assert result["verdict"]["level"] == "unknown"
            assert result["staticAnalysis"]["providers"][0]["status"] == "failed"
    asyncio.run(scenario())


@pytest.mark.parametrize("body", [
    {"url": "javascript:alert('PRIVATE')"}, {"url": "https://name:PRIVATE@example.test/"},
    {"url": "https://@example.test/PRIVATE"}, {"url": "https://example.test/", "PRIVATE": True},
    {"url": 1234}, {"url": "https://example.test/", "source": "PRIVATE"},
    {"url": "https://example.test/", "mode": "PRIVATE"},
])
def test_validation_never_echoes_rejected_values(body):
    async def scenario():
        async with client(create_public_app(threat_check=fake_google())) as api:
            response = await api.post("/api/analyze", json=body)
            assert response.status_code == 422
            assert "PRIVATE" not in response.text
            assert response.headers["cache-control"] == "no-store"
    asyncio.run(scenario())


def test_brand_check_is_not_claimed_by_a_static_lookup():
    async def scenario():
        async with client(create_public_app(threat_check=fake_google())) as api:
            result = (await api.post("/api/analyze", json={
                "url": "https://example.test/", "expectedBrand": "naver",
            })).json()
            assert result["verdict"]["level"] == "unknown"
            assert result["staticAnalysis"]["providers"][0]["status"] == "checked"
            assert result["staticAnalysis"]["providers"][0]["matched"] is False
            assert "사이트 화면과 동작을 검사하지 않아 판단을 보류" in result["verdict"]["reasons"][0]
    asyncio.run(scenario())


@pytest.mark.parametrize("headers", [
    {"Origin": "https://other.test"}, {"Origin": "null"},
    {"Origin": "https://qr.test/PRIVATE"}, {"Sec-Fetch-Site": "cross-site"},
])
def test_cross_site_browser_requests_are_rejected(headers):
    async def scenario():
        async with client(create_public_app(threat_check=fake_google())) as api:
            response = await api.post("/api/analyze", headers=headers, json={"url": "https://example.test/"})
            assert response.status_code == 403
            assert "PRIVATE" not in response.text
            assert response.headers["cache-control"] == "no-store"
    asyncio.run(scenario())


def test_configured_origins_and_same_origin_without_allowlist():
    async def scenario():
        async with client(create_public_app(threat_check=fake_google())) as api:
            assert (await api.post("/api/analyze", headers={"Origin": "https://qr.test"},
                                   json={"url": "https://example.test/"})).status_code == 200
        async with client(create_public_app(threat_check=fake_google(), allowed_origins=("https://front.test",))) as api:
            allowed = await api.post("/api/analyze", headers={"Origin": "https://front.test"},
                                     json={"url": "https://example.test/"})
            assert allowed.status_code == 200
            assert allowed.headers["access-control-allow-origin"] == "https://front.test"
            assert (await api.post("/api/analyze", headers={"Origin": "https://qr.test"},
                                   json={"url": "https://example.test/"})).status_code == 403
    asyncio.run(scenario())


def test_duplicate_origin_is_not_accepted():
    async def scenario():
        async with client(create_public_app(threat_check=fake_google())) as api:
            response = await api.post("/api/analyze", headers=[
                ("Origin", "https://qr.test"), ("Origin", "https://other.test"),
            ], json={"url": "https://example.test/"})
            assert response.status_code == 400
    asyncio.run(scenario())


@pytest.mark.parametrize("streamed", [False, True])
def test_oversized_bodies_are_rejected_before_lookup(streamed):
    called = []

    def lookup(url):
        called.append(url)
        return google_result()

    async def chunks():
        yield b"{" + b"x" * (MAX_REQUEST_BYTES // 2)
        yield b"y" * MAX_REQUEST_BYTES

    async def scenario():
        async with client(create_public_app(threat_check=lookup)) as api:
            response = await api.post("/api/analyze", content=chunks() if streamed else b"x" * (MAX_REQUEST_BYTES + 1))
            assert response.status_code == 413
            assert not called
            assert response.headers["cache-control"] == "no-store"
    asyncio.run(scenario())


def test_requests_do_not_accumulate_or_require_instance_affinity():
    async def scenario():
        application = create_public_app(threat_check=fake_google())
        assert not hasattr(application.state, "scans")
        async with client(application) as api:
            identifiers = []
            for _ in range(110):
                response = await api.post("/api/analyze", json={"url": "https://example.test/"})
                assert response.status_code == 200
                identifiers.append(response.json()["scanId"])
            assert len(set(identifiers)) == len(identifiers)
    asyncio.run(scenario())


def test_reports_are_unavailable_without_fabricated_statistics():
    async def scenario():
        async with client(create_public_app(threat_check=fake_google())) as api:
            response = await api.post("/api/scans/PRIVATE/reports", json={"scanId": "PRIVATE"})
            assert response.status_code == 503
            assert response.json()["reportAvailable"] is False
            assert "reportCount" not in response.json()
            assert "PRIVATE" not in response.text
            assert response.headers["cache-control"] == "no-store"
    asyncio.run(scenario())


def test_supported_methods_and_invalid_json_fail_closed():
    async def scenario():
        async with client(create_public_app(threat_check=fake_google())) as api:
            assert (await api.get("/api/analyze")).status_code == 405
            assert (await api.put("/api/analyze", json={"url": "https://example.test/"})).status_code == 405
            response = await api.post("/api/analyze", content=b'{"PRIVATE":', headers={"Content-Type": "application/json"})
            assert response.status_code == 422 and "PRIVATE" not in response.text
    asyncio.run(scenario())
