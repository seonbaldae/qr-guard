"""Actual local report receipts; threat observations are explicit test doubles."""

import asyncio

import httpx
import pytest

from app.config import Settings
from app.main import create_app
from tests.api.support import fake_google


def test_report_receipt_is_idempotent_and_visible_in_subsequent_scans():
    async def scenario():
        target = "https://example.test/phishing"
        application = create_app(Settings(), threat_check=fake_google([target]))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application), base_url="http://testserver",
        ) as client:
            first = (await client.post("/api/scans", json={"url": target})).json()["scanId"]
            before = (await client.get(f"/api/scans/{first}")).json()
            assert before["reportCount"] == 0
            assert before["isReported"] is False
            assert before["reportedByUser"] is False
            for _ in range(2):
                response = await client.post(f"/api/scans/{first}/reports", json={"scanId": first})
                assert response.status_code == 200
                assert response.json() == {
                    "scanId": first, "reportCount": 1, "isReported": True, "reportedByUser": True,
                }
                assert response.headers["cache-control"] == "no-store"
            after = (await client.get(f"/api/scans/{first}")).json()
            assert after["reportCount"] == 1 and after["reportedByUser"] is True

            second = (await client.post("/api/scans", json={"url": target})).json()["scanId"]
            another = (await client.get(f"/api/scans/{second}")).json()
            assert another["reportCount"] == 1
            assert another["isReported"] is True
            assert another["reportedByUser"] is False
            accepted = await client.post(f"/api/scans/{second}/reports", json={"scanId": second})
            assert accepted.json()["reportCount"] == 2
            assert (await client.get(f"/api/scans/{first}")).json()["reportCount"] == 2
    asyncio.run(scenario())


def test_report_count_does_not_create_a_malicious_verdict():
    async def scenario():
        application = create_app(Settings(), threat_check=fake_google())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application), base_url="http://testserver",
        ) as client:
            scan_id = (await client.post("/api/scans", json={"url": "https://example.test/"})).json()["scanId"]
            response = await client.post(f"/api/scans/{scan_id}/reports", json={"scanId": scan_id})
            assert response.status_code == 409
            assert (await client.get(f"/api/scans/{scan_id}")).json()["verdict"]["level"] == "no_known_threat"
            assert not application.state.report_receipts.submitted_scans
    asyncio.run(scenario())


@pytest.mark.parametrize("body, expected", [
    ({}, 422), ({"scanId": 123}, 422), ({"scanId": "other"}, 422),
    ({"scanId": "missing", "url": "https://secret-test-value.test/"}, 422),
    ({"scanId": "missing"}, 404),
])
def test_report_rejects_unknown_or_tampered_requests_without_echoing_values(body, expected):
    async def scenario():
        application = create_app(Settings(), threat_check=fake_google())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application), base_url="http://testserver",
        ) as client:
            response = await client.post("/api/scans/missing/reports", json=body)
            assert response.status_code == expected
            assert "secret-test-value" not in response.text
            assert not application.state.report_receipts.submitted_scans
    asyncio.run(scenario())


def test_report_counts_reset_with_server_process_state():
    from app.models import ScanReport, VerdictResult
    from app.reporting import ReportStore
    from datetime import datetime, timezone

    report = ScanReport(
        scan_id="one", status="completed", mode="static", requested_url="https://example.test/",
        updated_at=datetime.now(timezone.utc), verdict=VerdictResult(level="malicious", reasons=[]),
    )
    assert ReportStore().accept(report).report_count == 1
    assert ReportStore().receipt(report).report_count == 0
