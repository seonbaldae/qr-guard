"""Public API contract tests; no target-site network access."""

import importlib.util
import asyncio
import base64
from io import BytesIO

import httpx
from PIL import Image

from .support import fake_google, jobs_worker_from_result


def run_api(app, scenario):
    async def run():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver",
        ) as client:
            await scenario(client)
    asyncio.run(run())


def test_static_scan_connects_existing_analyzer():
    assert importlib.util.find_spec("app.main") is not None, "FastAPI application is missing"
    from app.main import create_app

    async def scenario(client):
        created = await client.post("/api/scans", json={"url": "http://192.0.2.1:8080/login"})
        assert created.status_code == 202
        queued = created.json()
        assert queued == {"scanId": queued["scanId"], "status": "queued", "mode": "static"}
        report = (await client.get(f"/api/scans/{queued['scanId']}")).json()
        assert report["status"] == "completed"
        assert report["mode"] == "static"
        assert {s["kind"] for s in report["staticAnalysis"]["signals"]} == {
            "ip_host", "nonstandard_port", "plain_http",
        }
        assert report["staticAnalysis"]["providers"][0]["matched"] is None
        assert report["verdict"]["level"] == "unknown"
        assert report["sandboxAnalysis"]["skipReason"] == "static_only"
        assert (await client.get(f"/api/scans/{queued['scanId']}/screenshot")).status_code == 409

    run_api(create_app(), scenario)


def test_f1_google_match_is_malicious_without_worker():
    assert importlib.util.find_spec("app.config") is not None, "Feed configuration is missing"
    from app.config import Settings
    from app.main import create_app

    async def scenario(client):
        response = await client.post("/api/scans", json={
            "url": "https://example.test/phishing", "mode": "sandbox",
        })
        assert response.status_code == 202
        report = (await client.get(f"/api/scans/{response.json()['scanId']}")).json()
        assert report["verdict"]["level"] == "malicious"
        assert report["sandboxAnalysis"]["skipReason"] == "known_malicious"
        assert report["sandboxAnalysis"]["screenshot"]["status"] == "skipped"
        assert report["staticAnalysis"]["providers"][0]["matched"] is True
        known = {e["id"] for e in report["evidence"]}
        assert set(report["verdict"]["evidenceIds"]) <= known
        assert report["verdict"]["evidenceIds"]

    run_api(create_app(Settings(), threat_check=fake_google(["https://example.test/phishing"])), scenario)


def test_sandbox_is_blocked_without_configured_safe_worker():
    from app.main import create_app

    async def scenario(client):
        response = await client.post("/api/scans", json={
            "url": "https://example.test/", "mode": "sandbox",
        })
        report = (await client.get(f"/api/scans/{response.json()['scanId']}")).json()
        assert report["status"] == "completed"
        assert report["sandboxAnalysis"]["status"] == "blocked"
        assert report["sandboxAnalysis"]["skipReason"] is None
        assert report["sandboxAnalysis"]["finalUrl"] is None
        assert report["sandboxAnalysis"]["screenshot"]["available"] is False
        assert report["verdict"]["level"] == "unknown"

    run_api(create_app(), scenario)


def png_bytes():
    output = BytesIO()
    Image.new("RGB", (2, 2), "white").save(output, format="PNG")
    return output.getvalue()


def test_f2_worker_contract_returns_png_and_no_known_threat():
    assert importlib.util.find_spec("app.worker") is not None, "Worker adapter is missing"
    from app.config import Settings
    from app.main import create_app

    png = png_bytes()
    calls = []

    def worker(request):
        import json
        assert str(request.url) == "http://worker:8001/internal/jobs"
        body = json.loads(request.content)
        assert set(body) == {"scanId", "url", "timeoutMs"}
        assert body["url"] == "https://demo.example.test/"
        calls.append(body)
        return httpx.Response(200, json={
            "finalUrl": body["url"], "httpStatus": 200, "pageTitle": "Controlled demo",
            "passwordFieldCount": 0, "sensitiveFieldTypes": [], "forms": [],
            "requestHosts": ["demo.example.test"], "redirected": False,
            "screenshotBase64": base64.b64encode(png).decode(), "limitations": [],
        })

    async def scenario(client):
        response = await client.post("/api/scans", json={
            "url": "https://demo.example.test/", "mode": "sandbox",
        })
        scan_id = response.json()["scanId"]
        report = (await client.get(f"/api/scans/{scan_id}")).json()
        assert report["verdict"]["level"] == "no_known_threat"
        assert report["sandboxAnalysis"]["status"] == "completed"
        assert report["sandboxAnalysis"]["screenshot"]["available"] is True
        image = await client.get(f"/api/scans/{scan_id}/screenshot")
        assert image.status_code == 200
        assert image.headers["content-type"] == "image/png"
        assert image.content == png
        assert "screenshotBase64" not in str(report)
        assert len(calls) == 1

    settings = Settings(
        worker_url="http://worker:8001",
        demo_origins=("https://demo.example.test",), worker_egress_verified=True,
    )
    run_api(create_app(settings, worker_transport=httpx.MockTransport(jobs_worker_from_result(worker)), threat_check=fake_google()), scenario)


def test_password_and_expected_brand_mismatch_are_suspicious():
    from app.config import Settings
    from app.main import create_app

    def worker(_request):
        return httpx.Response(200, json={
            "finalUrl": "https://demo.example.test/login", "httpStatus": 200, "pageTitle": "Demo",
            "passwordFieldCount": 1, "sensitiveFieldTypes": ["password"], "forms": [],
            "requestHosts": [], "redirected": False,
            "screenshotBase64": base64.b64encode(png_bytes()).decode(), "limitations": [],
        })

    async def scenario(client):
        response = await client.post("/api/scans", json={
            "url": "https://demo.example.test/login", "mode": "sandbox", "expectedBrand": "naver",
        })
        report = (await client.get(f"/api/scans/{response.json()['scanId']}")).json()
        assert report["verdict"]["level"] == "suspicious"
        evidence = {e["id"]: e for e in report["evidence"]}
        assert {evidence[key]["kind"] for key in report["verdict"]["evidenceIds"]} == {
            "brand_domain_mismatch", "password_field",
        }
        assert report["staticAnalysis"]["providers"][0]["matched"] is None
        assert report["sandboxAnalysis"]["signals"][0]["evidenceIds"]

    settings = Settings(
        worker_url="http://worker:8001", demo_origins=("https://demo.example.test",),
        worker_egress_verified=True,
    )
    run_api(create_app(settings, worker_transport=httpx.MockTransport(jobs_worker_from_result(worker))), scenario)


class FakeBrandAnalyzer:
    enabled = True

    def __init__(self, signal):
        self.signal = signal

    async def analyze(self, _scan_id, _final_url, _png):
        from app.phishpedia import BrandAnalysis
        candidate = "Naver" if self.signal != "brand_unidentified" else None
        return BrandAnalysis.model_validate({
            "engine": "phishpedia", "status": "completed", "signal": self.signal,
            "candidateBrand": candidate,
            "referenceDomains": ["naver.com"] if candidate else [],
            "rawSimilarity": 0.97 if candidate else None, "detectedLogoCount": 1 if candidate else 0,
            "domainComparison": {
                "status": "mismatch" if self.signal == "brand_domain_inconsistency" else
                          "match" if self.signal == "brand_domain_match" else "not_evaluated",
                "actualHost": "demo.example.test", "matchedReferenceDomain": None,
            },
        })


class FailedBrandAnalyzer:
    enabled = True

    async def analyze(self, _scan_id, _final_url, _png):
        from app.phishpedia import PhishpediaError
        raise PhishpediaError("phishpedia_failed")


def test_phishpedia_brand_domain_mismatch_is_suspicious_without_user_brand_hint():
    from app.config import Settings
    from app.main import create_app

    def worker(_request):
        return httpx.Response(200, json={
            "finalUrl": "https://demo.example.test/login", "httpStatus": 200,
            "pageTitle": "Naver", "passwordFieldCount": 0, "sensitiveFieldTypes": [],
            "forms": [], "requestHosts": [], "redirected": False,
            "screenshotBase64": base64.b64encode(png_bytes()).decode(), "limitations": [],
        })

    async def scenario(client):
        accepted = await client.post("/api/scans", json={
            "url": "https://demo.example.test/login", "mode": "sandbox",
        })
        report = (await client.get(f"/api/scans/{accepted.json()['scanId']}")).json()
        assert report["verdict"]["level"] == "suspicious"
        assert report["verdict"]["evidenceIds"] == ["ev-phishpedia-brand"]
        assert report["sandboxAnalysis"]["signals"][-1]["kind"] == "brand_domain_mismatch"
        assert report["evidence"][-1]["data"]["candidateBrand"] == "Naver"

    settings = Settings(
        worker_url="http://worker:8001", demo_origins=("https://demo.example.test",),
        worker_egress_verified=True, phishpedia_image="seonbaldae-phishpedia",
    )
    run_api(create_app(
        settings, worker_transport=httpx.MockTransport(jobs_worker_from_result(worker)),
        threat_check=fake_google(), brand_analyzer=FakeBrandAnalyzer("brand_domain_inconsistency"),
    ), scenario)


def test_phishpedia_unidentified_brand_never_publishes_clean_verdict():
    from app.config import Settings
    from app.main import create_app

    def worker(_request):
        return httpx.Response(200, json={
            "finalUrl": "https://demo.example.test/", "httpStatus": 200,
            "pageTitle": "Demo", "passwordFieldCount": 0, "sensitiveFieldTypes": [],
            "forms": [], "requestHosts": [], "redirected": False,
            "screenshotBase64": base64.b64encode(png_bytes()).decode(), "limitations": [],
        })

    async def scenario(client):
        accepted = await client.post("/api/scans", json={
            "url": "https://demo.example.test/", "mode": "sandbox",
        })
        report = (await client.get(f"/api/scans/{accepted.json()['scanId']}")).json()
        assert report["verdict"]["level"] == "unknown"
        assert any("브랜드" in item for item in report["verdict"]["limitations"])

    settings = Settings(
        worker_url="http://worker:8001", demo_origins=("https://demo.example.test",),
        worker_egress_verified=True, phishpedia_image="seonbaldae-phishpedia",
    )
    run_api(create_app(
        settings, worker_transport=httpx.MockTransport(jobs_worker_from_result(worker)),
        threat_check=fake_google(), brand_analyzer=FakeBrandAnalyzer("brand_unidentified"),
    ), scenario)


def test_phishpedia_failure_never_publishes_clean_verdict():
    from app.config import Settings
    from app.main import create_app

    def worker(_request):
        return httpx.Response(200, json={
            "finalUrl": "https://demo.example.test/", "httpStatus": 200,
            "pageTitle": "Demo", "passwordFieldCount": 0, "sensitiveFieldTypes": [],
            "forms": [], "requestHosts": [], "redirected": False,
            "screenshotBase64": base64.b64encode(png_bytes()).decode(), "limitations": [],
        })

    async def scenario(client):
        accepted = await client.post("/api/scans", json={
            "url": "https://demo.example.test/", "mode": "sandbox",
        })
        report = (await client.get(f"/api/scans/{accepted.json()['scanId']}")).json()
        assert report["status"] == "completed"
        assert report["verdict"]["level"] == "unknown"
        assert any("브랜드" in item for item in report["sandboxAnalysis"]["limitations"])

    settings = Settings(
        worker_url="http://worker:8001", demo_origins=("https://demo.example.test",),
        worker_egress_verified=True, phishpedia_image="seonbaldae-phishpedia",
    )
    run_api(create_app(
        settings, worker_transport=httpx.MockTransport(jobs_worker_from_result(worker)),
        threat_check=fake_google(), brand_analyzer=FailedBrandAnalyzer(),
    ), scenario)
