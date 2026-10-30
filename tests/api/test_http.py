"""Frontend-facing HTTP behavior and request safety."""

import asyncio

import httpx
import pytest

from app.config import Settings
from app.main import create_app


def test_frontend_cors_uses_explicit_origin():
    async def scenario():
        application = create_app(Settings(cors_origins=("http://localhost:5173",)))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application), base_url="http://testserver",
        ) as client:
            allowed = await client.options("/api/scans", headers={
                "Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            })
            assert allowed.status_code == 200
            assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"
            denied = await client.options("/api/scans", headers={
                "Origin": "https://other.example.test", "Access-Control-Request-Method": "POST",
            })
            assert "access-control-allow-origin" not in denied.headers
    asyncio.run(scenario())


def test_scan_store_has_a_hard_capacity_limit():
    async def scenario():
        application = create_app(Settings(max_scans=1))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application), base_url="http://testserver",
        ) as client:
            first = await client.post("/api/scans", json={"url": "https://example.test/"})
            assert first.status_code == 202
            second = await client.post("/api/scans", json={"url": "https://example.test/"})
            assert second.status_code == 503
            assert len(application.state.scans.reports) == 1
            report = await client.get(f"/api/scans/{first.json()['scanId']}")
            assert report.status_code == 200
            assert report.headers["cache-control"] == "no-store"
    asyncio.run(scenario())


@pytest.mark.parametrize("body", [
    {}, {"url": None}, {"url": 123}, {"url": "example.com"},
    {"url": "javascript:alert(1)"}, {"url": "file:///etc/passwd"},
    {"url": "https://example.com/", "mode": "other"},
    {"url": "https://example.com/", "source": "other"},
    {"url": "https://example.com/", "unexpected": "secret-test-value"},
    {"url": "https://user:secret-test-value@example.com:99999/?token=secret-test-value"},
])
def test_validation_does_not_echo_rejected_values(body):
    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(Settings())), base_url="http://testserver",
        ) as client:
            response = await client.post("/api/scans", json=body)
            assert response.status_code == 422
            assert "secret-test-value" not in response.text
            assert not any("input" in error for error in response.json()["detail"])
    asyncio.run(scenario())


def test_unknown_ids_and_missing_routes():
    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(Settings())), base_url="http://testserver",
        ) as client:
            assert (await client.get("/api/scans/missing")).status_code == 404
            assert (await client.get("/api/scans/missing/screenshot")).status_code == 404
            assert (await client.post("/api/scans/missing/cancel")).status_code == 404
            assert (await client.get("/api/health")).json() == {"status": "ok"}
    asyncio.run(scenario())


def test_unexpected_worker_error_finishes_all_pending_states():
    async def broken_worker(*_args, **_kwargs):
        raise RuntimeError("secret-test-value")

    async def scenario():
        application = create_app(Settings())
        application.state.scans.worker.analyze = broken_worker
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application), base_url="http://testserver",
        ) as client:
            created = await client.post("/api/scans", json={"url": "https://example.test/", "mode": "sandbox"})
            report = (await client.get(f"/api/scans/{created.json()['scanId']}")).json()
            assert report["status"] == "failed"
            assert report["sandboxAnalysis"]["status"] == "failed"
            assert report["sandboxAnalysis"]["screenshot"]["status"] == "failed"
            assert report["verdict"]["level"] == "unknown"
            assert "secret-test-value" not in str(report)
    asyncio.run(scenario())
