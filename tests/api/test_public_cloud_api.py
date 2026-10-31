"""Public browser orchestration without credentials, SDK calls or retained jobs."""

import asyncio
import base64
import io

import httpx
import pytest
from PIL import Image

from app.cloud_worker import CloudBrowserResult, CloudWorkerError
from app.public_api import create_public_app
from tests.api.support import fake_google, google_result

TARGET = "https://source.example.test/path"
FINAL = "https://destination.example.test/login"


def png_bytes(color="white"):
    buffer = io.BytesIO()
    Image.new("RGB", (2, 2), color).save(buffer, format="PNG")
    return buffer.getvalue()


class FakeCloud:
    enabled = True

    def __init__(self, *, changes=None, error=None, png=None):
        self.calls = []
        self.changes, self.error = changes or {}, error
        self.png = png_bytes() if png is None else png

    async def analyze(self, scan_id, url):
        self.calls.append((scan_id, url))
        if self.error:
            raise self.error
        body = {
            "scanId": scan_id, "status": "completed", "finalUrl": FINAL, "httpStatus": 200,
            "inspectionComplete": True, "screenshotStatus": "ready", "capturedAt": "2026-10-31T04:00:00Z",
            "domAnalysis": {"pageTitle": "관찰한 화면", "passwordFieldCount": 1, "sensitiveFieldTypes": ["password"],
                            "forms": [{"method": "POST", "actionHost": "destination.example.test"}]},
            "networkAnalysis": {"requestHosts": ["destination.example.test"], "requestCount": 3, "blockedRequestCount": 0},
            "redirectAnalysis": {"redirected": True, "finalUrl": FINAL, "redirectChain": [
                {"from": TARGET, "to": FINAL, "statusCode": 302, "type": "http", "blocked": False},
            ]},
            "limitations": ["열린 Shadow DOM을 관찰했습니다."],
        }
        body.update(self.changes)
        return CloudBrowserResult.model_validate(body), self.png


def client(worker, lookup=None):
    application = create_public_app(threat_check=lookup or fake_google(), cloud_worker=worker)
    assert not hasattr(application.state, "scans")
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="https://qr.test")


def scan(worker=None, lookup=None):
    worker = worker or FakeCloud()

    async def scenario():
        async with client(worker, lookup) as api:
            response = await api.post("/api/analyze", json={"url": TARGET, "mode": "sandbox"})
            assert response.status_code == 200
            return response.json(), response
    result, response = asyncio.run(scenario())
    return result, worker, response


def test_capabilities_change_only_when_cloud_is_available():
    async def scenario():
        async with client(FakeCloud()) as api:
            capabilities = (await api.get("/api/capabilities")).json()
            assert capabilities == {"scanTransport": "direct", "scanMode": "sandbox", "analysisScope": "sandbox",
                                    "previewAvailable": True, "reportAvailable": False}
            assert (await api.get("/api/health")).json() == {"status": "ok", **capabilities}
    asyncio.run(scenario())


def test_completed_visit_returns_real_png_and_facts_without_claiming_clear():
    result, worker, response = scan()
    assert result["mode"] == "sandbox" and result["analysisScope"] == "sandbox" and result["status"] == "completed"
    assert worker.calls == [(result["scanId"], TARGET)]
    sandbox = result["sandboxAnalysis"]
    assert sandbox["status"] == "completed" and sandbox["finalUrl"] == FINAL and sandbox["httpStatus"] == 200
    assert sandbox["screenshot"]["status"] == "ready" and sandbox["screenshot"]["available"]
    assert sandbox["screenshot"]["capturedAt"].startswith("2026-10-31T04:00:00")
    preview = result["previewImage"]
    assert preview["scanId"] == result["scanId"] and preview["mimeType"] == "image/png"
    assert base64.b64decode(preview["base64"], validate=True) == png_bytes()
    assert result["verdict"]["level"] == "unknown" and "사칭 여부" in result["verdict"]["reasons"][0]
    assert result["reportCount"] is None and result["isReported"] is None and result["reportAvailable"] is False
    assert result["previewAvailable"] is True
    facts = {item["kind"]: item for item in result["evidence"]}
    assert facts["dom_observation"]["data"]["passwordFieldCount"] == 1
    assert facts["network_observation"]["data"] == {"requestCount": 3, "blockedRequestCount": 0, "hostCount": 1}
    assert facts["redirect_observation"]["data"] == {"redirected": True, "redirectCount": 1}
    evidence_ids = {item["id"] for item in result["evidence"]}
    assert all(set(signal["evidenceIds"]) <= evidence_ids for signal in sandbox["signals"])
    assert all(isinstance(value, (str, int, float, bool, type(None))) for item in result["evidence"] for value in (item["data"] or {}).values())
    assert any("판별 모델" in item for item in result["verdict"]["limitations"])
    assert "주소만 검사" not in " ".join(result["verdict"]["limitations"])
    assert response.headers["cache-control"] == "no-store"


def test_known_threat_skips_browser_and_never_fabricates_preview():
    result, worker, _ = scan(lookup=fake_google([TARGET]))
    assert worker.calls == []
    assert result["mode"] == "sandbox" and result["analysisScope"] == "sandbox"
    assert result["verdict"]["level"] == "malicious"
    assert result["sandboxAnalysis"]["status"] == "skipped"
    assert result["sandboxAnalysis"]["skipReason"] == "known_malicious"
    assert result["sandboxAnalysis"]["screenshot"]["available"] is False
    assert result["sandboxAnalysis"]["finalUrl"] is None
    assert "previewImage" not in result and result["previewAvailable"] is False


def test_final_destination_threat_overrides_initial_negative_with_linked_evidence():
    lookups = []

    def lookup(url):
        lookups.append(url)
        return google_result(matched=url == FINAL)

    result, worker, _ = scan(lookup=lookup)
    assert lookups == [TARGET, FINAL] and worker.calls
    assert result["staticAnalysis"]["providers"][0]["matched"] is False
    assert result["verdict"]["level"] == "malicious"
    assert result["verdict"]["evidenceIds"] == ["final-ev-google"]
    assert "final-ev-google" in {item["id"] for item in result["evidence"]}
    assert any(item["id"] == "final-sig-google" and item["evidenceIds"] == ["final-ev-google"]
               for item in result["sandboxAnalysis"]["signals"])


def test_partial_observer_failure_keeps_verified_png_and_actual_final_address():
    worker = FakeCloud(changes={"status": "failed", "inspectionComplete": False, "domAnalysis": None})
    result, _, _ = scan(worker)
    assert result["sandboxAnalysis"]["status"] == "failed"
    assert result["sandboxAnalysis"]["finalUrl"] == FINAL
    assert result["sandboxAnalysis"]["screenshot"]["available"] is True
    assert base64.b64decode(result["previewImage"]["base64"]) == png_bytes()
    assert result["verdict"]["level"] == "unknown"
    assert not any(item["kind"] == "dom_observation" for item in result["evidence"])


@pytest.mark.parametrize("error,code,status", [
    (CloudWorkerError("worker_timeout"), "worker_timeout", "failed"),
    (TimeoutError("PRIVATE transport token"), "worker_timeout", "failed"),
    (RuntimeError("PRIVATE raw SDK output"), "worker_unreachable", "failed"),
    (CloudWorkerError("unsafe_target", blocked=True), "unsafe_target", "blocked"),
])
def test_failed_cloud_observation_stays_unknown_and_hides_transport_details(error, code, status):
    result, _, response = scan(FakeCloud(error=error))
    assert result["status"] == "completed" and result["verdict"]["level"] == "unknown"
    assert result["sandboxAnalysis"]["status"] == status and result["sandboxAnalysis"]["errorCode"] == code
    assert result["sandboxAnalysis"]["finalUrl"] is None
    assert result["sandboxAnalysis"]["screenshot"]["available"] is False and "previewImage" not in result
    assert "PRIVATE" not in response.text


def test_policy_blocked_metadata_preserves_facts_but_prevents_complete_result():
    network = {"requestHosts": ["destination.example.test"], "requestCount": 3, "blockedRequestCount": 1}
    result, _, _ = scan(FakeCloud(changes={"networkAnalysis": network}))
    assert result["sandboxAnalysis"]["status"] == "blocked" and result["verdict"]["level"] == "unknown"
    assert result["previewImage"] and result["sandboxAnalysis"]["screenshot"]["available"]


def test_scan_identifier_mismatch_cannot_return_another_requests_image():
    result, _, _ = scan(FakeCloud(changes={"scanId": "another_scan"}))
    assert result["sandboxAnalysis"]["errorCode"] == "worker_invalid_response"
    assert result["sandboxAnalysis"]["finalUrl"] is None and "previewImage" not in result


def test_invalid_png_is_rejected_again_at_the_public_response_boundary():
    result, _, _ = scan(FakeCloud(png=b"not an image"))
    assert result["sandboxAnalysis"]["status"] == "failed"
    assert result["sandboxAnalysis"]["errorCode"] == "invalid_screenshot"
    assert result["verdict"]["level"] == "unknown" and "previewImage" not in result


def test_concurrent_requests_have_independent_ids_images_and_threat_branches():
    worker = FakeCloud()

    async def scenario():
        async with client(worker, fake_google([TARGET])) as api:
            first, second = await asyncio.gather(
                api.post("/api/analyze", json={"url": TARGET}),
                api.post("/api/analyze", json={"url": "https://other.example.test/"}),
            )
            dangerous, observed = first.json(), second.json()
            assert dangerous["scanId"] != observed["scanId"]
            assert dangerous["verdict"]["level"] == "malicious" and "previewImage" not in dangerous
            assert observed["verdict"]["level"] == "unknown"
            assert observed["previewImage"]["scanId"] == observed["scanId"]
            assert worker.calls == [(observed["scanId"], "https://other.example.test/")]
            assert (await api.get(f'/api/scans/{observed["scanId"]}')).status_code == 404
    asyncio.run(scenario())


@pytest.mark.parametrize("verified,image,enabled", [
    ("false", "worker@sha256:" + "a" * 64, False),
    ("true", "", False), ("true", "worker:latest", False),
    ("true", "worker@sha256:" + "a" * 64, True),
])
def test_environment_requires_both_verified_flag_and_pinned_image(monkeypatch, verified, image, enabled):
    monkeypatch.setenv("QR_GUARD_CLOUD_WORKER_VERIFIED", verified)
    monkeypatch.setenv("QR_GUARD_CLOUD_WORKER_IMAGE", image)
    monkeypatch.delenv("QR_GUARD_CLOUD_WORKER_SNAPSHOT", raising=False)

    async def scenario():
        application = create_public_app(threat_check=fake_google())
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="https://qr.test") as api:
            result = (await api.get("/api/capabilities")).json()
            assert result["previewAvailable"] is enabled
            assert result["scanMode"] == ("sandbox" if enabled else "static")
    asyncio.run(scenario())


@pytest.mark.parametrize("verified,image,snapshot,enabled", [
    ("true", "", "snap_clean123", True), ("false", "", "snap_clean123", False),
    ("true", "", "snapshot_bad", False), ("true", "", "snap_bad/id", False),
    ("true", "worker@sha256:" + "a" * 64, "snap_clean123", False),
])
def test_snapshot_configuration_uses_same_verification_gate_and_rejects_ambiguous_sources(
        monkeypatch, verified, image, snapshot, enabled):
    monkeypatch.setenv("QR_GUARD_CLOUD_WORKER_VERIFIED", verified)
    monkeypatch.setenv("QR_GUARD_CLOUD_WORKER_IMAGE", image)
    monkeypatch.setenv("QR_GUARD_CLOUD_WORKER_SNAPSHOT", snapshot)

    async def scenario():
        application = create_public_app(threat_check=fake_google())
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application), base_url="https://qr.test") as api:
            result = (await api.get("/api/capabilities")).json()
            assert result["previewAvailable"] is enabled
            assert result["scanMode"] == ("sandbox" if enabled else "static")
    asyncio.run(scenario())
