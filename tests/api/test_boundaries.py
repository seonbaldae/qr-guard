"""Boundary tests. Worker responses below are explicit HTTP test doubles, not live analysis."""

import asyncio
import base64
from io import BytesIO
from dataclasses import replace
import os

import httpx
from PIL import Image
import pytest

from app.config import Settings
from app.main import create_app
from app.static_adapter import FeedSnapshot


def worker_payload(**changes):
    image = BytesIO()
    Image.new("RGB", (2, 2)).save(image, format="PNG")
    data = {
        "finalUrl": "https://demo.example.test/", "httpStatus": 200, "pageTitle": "Demo",
        "passwordFieldCount": 0, "sensitiveFieldTypes": [], "forms": [],
        "requestHosts": [], "redirected": False,
        "screenshotBase64": base64.b64encode(image.getvalue()).decode(), "limitations": [],
    }
    data.update(changes)
    return data


def scan(settings, handler, body=None):
    async def run():
        app = create_app(settings, worker_transport=httpx.MockTransport(handler))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver",
        ) as client:
            created = await client.post("/api/scans", json=body or {
                "url": "https://demo.example.test/", "mode": "sandbox",
            })
            assert created.status_code == 202
            scan_id = created.json()["scanId"]
            report = (await client.get(f"/api/scans/{scan_id}")).json()
            screenshot = await client.get(f"/api/scans/{scan_id}/screenshot")
            known = {e["id"] for e in report["evidence"]}
            for section in [report["staticAnalysis"], report["sandboxAnalysis"]]:
                for signal in section["signals"]:
                    assert set(signal["evidenceIds"]) <= known
            assert set(report["verdict"]["evidenceIds"]) <= known
            return report, screenshot
    return asyncio.run(run())


def settings_with_feed(tmp_path, **changes):
    feed = tmp_path / "feed.txt"
    feed.write_text("https://listed.example.test/\n", encoding="utf-8")
    settings = Settings(feed_path=feed, worker_url="http://worker:8001",
                        demo_origins=("https://demo.example.test",), worker_egress_verified=True)
    return replace(settings, **changes)


@pytest.mark.parametrize("target", [
    "http://169.254.169.254/", "http://127.0.0.1/", "http://[::1]/",
    "https://127.1/", "https://0177.0.0.1/", "https://0x7f.0.0.1/",
    "https://demo.example.test.attacker.test/", "https://other.example.test/",
    "https://demo.example.test:8443/", "http://demo.example.test/",
    "https://user@demo.example.test/",
])
def test_disallowed_targets_never_reach_worker(tmp_path, target):
    def forbidden(_request):
        pytest.fail("Disallowed target reached Worker")
    report, image = scan(settings_with_feed(tmp_path), forbidden, {"url": target, "mode": "sandbox"})
    assert report["sandboxAnalysis"]["status"] == "blocked"
    assert report["verdict"]["level"] == "unknown"
    assert image.status_code == 409


def test_worker_cannot_be_enabled_by_allowlist_alone(tmp_path):
    def forbidden(_request):
        pytest.fail("Worker called without network egress verification")
    report, _ = scan(settings_with_feed(tmp_path, worker_egress_verified=False), forbidden)
    assert report["sandboxAnalysis"]["errorCode"] == "worker_egress_unverified"


@pytest.mark.parametrize("failure", ["timeout", "unreachable", "403", "500", "302", "invalid_json"])
def test_worker_failures_never_mean_no_known_threat(tmp_path, failure):
    def worker(request):
        if failure == "timeout":
            raise httpx.ReadTimeout("do-not-expose", request=request)
        if failure == "unreachable":
            raise httpx.ConnectError("do-not-expose", request=request)
        if failure == "invalid_json":
            return httpx.Response(200, content=b"not JSON do-not-expose")
        return httpx.Response(int(failure), headers={"location": "https://not-allowed.test"})
    report, image = scan(settings_with_feed(tmp_path), worker)
    assert report["verdict"]["level"] == "unknown"
    assert report["sandboxAnalysis"]["status"] in {"failed", "blocked"}
    assert report["sandboxAnalysis"]["finalUrl"] is None
    assert "do-not-expose" not in str(report)
    assert image.status_code == 409


@pytest.mark.parametrize("changes", [
    {"finalUrl": "http://127.0.0.1/"}, {"finalUrl": None}, {"httpStatus": None},
    {"httpStatus": 503}, {"screenshotBase64": "invalid"},
    {"screenshotBase64": base64.b64encode(b"<script>not png</script>").decode()},
    {"passwordFieldCount": -1}, {"passwordFieldCount": "1"},
])
def test_bad_worker_results_do_not_expose_screenshots(tmp_path, changes):
    report, image = scan(settings_with_feed(tmp_path), lambda _: httpx.Response(
        200, json=worker_payload(**changes),
    ))
    assert report["verdict"]["level"] == "unknown"
    assert report["sandboxAnalysis"]["screenshot"]["available"] is False
    assert image.status_code == 409


def test_plain_login_alone_is_not_suspicious(tmp_path):
    report, _ = scan(settings_with_feed(tmp_path), lambda _: httpx.Response(
        200, json=worker_payload(passwordFieldCount=1, sensitiveFieldTypes=["password"]),
    ))
    assert report["verdict"]["level"] == "no_known_threat"
    assert {e["kind"] for e in report["evidence"]} == {"password_field"}


@pytest.mark.parametrize("reason, marker", [
    ("CAPTCHA prevented inspection https://user:do-not-expose@demo.example.test/", "CAPTCHA"),
    ("incomplete DOM token=do-not-expose", "DOM"),
])
def test_incomplete_observation_is_unknown(tmp_path, reason, marker):
    report, _ = scan(settings_with_feed(tmp_path), lambda _: httpx.Response(
        200, json=worker_payload(limitations=[reason]),
    ))
    assert report["verdict"]["level"] == "unknown"
    assert any(marker in item for item in report["sandboxAnalysis"]["limitations"])
    assert any(marker in item for item in report["verdict"]["limitations"])
    assert "do-not-expose" not in str(report)


def test_unknown_brand_is_not_guessed(tmp_path):
    report, _ = scan(settings_with_feed(tmp_path), lambda _: httpx.Response(
        200, json=worker_payload(passwordFieldCount=1),
    ), {"url": "https://demo.example.test/", "mode": "sandbox", "expectedBrand": "unverified"})
    assert report["verdict"]["level"] == "unknown"
    assert not any(e["kind"] == "brand_domain_mismatch" for e in report["evidence"])


@pytest.mark.parametrize("mode", ["static", "sandbox"])
def test_known_match_never_calls_worker(tmp_path, mode):
    def forbidden(_request):
        pytest.fail("Known phishing URL reached Worker")
    report, _ = scan(settings_with_feed(tmp_path), forbidden, {
        "url": "https://listed.example.test/", "mode": mode,
    })
    assert report["verdict"]["level"] == "malicious"


def test_redirect_to_feed_match_is_malicious_after_worker_completes(tmp_path):
    settings = settings_with_feed(tmp_path, demo_origins=(
        "https://demo.example.test", "https://listed.example.test",
    ))
    final_url = "https://listed.example.test/?token=private"
    assert settings.feed_path is not None
    settings.feed_path.write_text(final_url + "\n", encoding="utf-8")
    report, image = scan(settings, lambda _: httpx.Response(
        200, json=worker_payload(finalUrl=final_url, redirected=True),
    ))
    assert report["verdict"]["level"] == "malicious"
    assert report["sandboxAnalysis"]["status"] == "completed"
    assert report["sandboxAnalysis"]["screenshot"]["status"] == "ready"
    assert image.status_code == 200
    feed_evidence = [e for e in report["evidence"] if e["kind"] == "threat_feed_match"]
    assert feed_evidence and feed_evidence[0]["id"] in report["verdict"]["evidenceIds"]
    assert final_url not in str(feed_evidence) and "private" not in str(feed_evidence)


def test_static_only_never_calls_worker(tmp_path):
    def forbidden(_request):
        pytest.fail("Static mode called Worker")
    report, _ = scan(settings_with_feed(tmp_path), forbidden, {
        "url": "https://demo.example.test/", "mode": "static",
    })
    assert report["sandboxAnalysis"]["status"] == "not_requested"
    assert report["verdict"]["level"] == "no_known_threat"
    assert report["verdict"]["limitations"]


def test_feed_match_is_full_url_not_domain(tmp_path):
    report, _ = scan(settings_with_feed(tmp_path), lambda _: httpx.Response(
        200, json=worker_payload(),
    ), {"url": "https://listed.example.test/different-path", "mode": "static"})
    assert report["staticAnalysis"]["providers"][0]["matched"] is False
    assert report["verdict"]["level"] != "malicious"


def test_feed_becoming_stale_during_worker_yields_unknown(tmp_path, monkeypatch):
    original_lookup = FeedSnapshot.lookup
    lookups = []

    def lookup(self, url, max_age):
        result = original_lookup(self, url, max_age)
        lookups.append(result)
        return result if len(lookups) == 1 else result.model_copy(update={"status": "stale"})

    monkeypatch.setattr(FeedSnapshot, "lookup", lookup)
    report, _ = scan(settings_with_feed(tmp_path), lambda _: httpx.Response(
        200, json=worker_payload(),
    ))
    assert len(lookups) == 2
    assert lookups[0].status == "checked" and lookups[0].matched is False
    assert report["sandboxAnalysis"]["status"] == "completed"
    assert report["verdict"]["level"] == "unknown"


def test_stale_feed_does_not_prove_absence_of_threats(tmp_path):
    settings = settings_with_feed(tmp_path)
    assert settings.feed_path is not None
    os.utime(settings.feed_path, (1, 1))
    report, _ = scan(settings, lambda _: httpx.Response(200, json=worker_payload()))
    assert report["staticAnalysis"]["providers"][0]["status"] == "stale"
    assert report["verdict"]["level"] == "unknown"
